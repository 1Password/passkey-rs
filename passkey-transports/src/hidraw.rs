//! Linux HIDRAW transport for talking CTAPHID to USB security keys.
//!
//! This module enumerates FIDO-capable HID devices via `udev`, then exposes an async wrapper around
//! `/dev/hidrawN` built on `tokio::io::unix::AsyncFd`. The wrapper handles framing CTAPHID
//! [`Message`]s into 64-byte packets, and provides a convenience method for performing a fresh
//! `CTAPHID_INIT` handshake.
//!
//! Callers are expected to drive the CTAP conversation that follows using [`HidDevice::send`] and
//! [`HidDevice::recv`].

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hidparser::ReportField;
use rand::Rng;
use rand::rngs::ChaCha20Rng;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::time::timeout;

use crate::hid::{ChannelHandler, Command, CreationError, MAX_PACKET_SIZE, Message};

/// HID usage page assigned to the FIDO Alliance for U2F / CTAP authenticators.
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// CTAPHID broadcast channel identifier used during `CTAPHID_INIT`.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// Maximum size of an HID report descriptor as defined by the Linux kernel
/// (`HID_MAX_DESCRIPTOR_SIZE` in `linux/hid.h`).
const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

/// Default timeout for a single packet read while waiting for an authenticator
/// response. The CTAPHID spec mandates `KEEPALIVE` packets every 100 ms while a
/// transaction is in progress, so anything longer than a couple seconds without
/// activity indicates the device has stopped responding.
const PACKET_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Information about a discovered FIDO-capable HID device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Path to the `/dev/hidrawN` device file.
    pub path: PathBuf,
    /// USB vendor identifier, if available.
    pub vendor_id: Option<u16>,
    /// USB product identifier, if available.
    pub product_id: Option<u16>,
    /// Human-readable device name reported by the HID descriptor, if available.
    pub name: Option<String>,
}

/// Errors that may occur while talking to a HIDRAW device.
#[derive(Debug)]
#[non_exhaustive]
pub enum HidrawError {
    /// An I/O error occurred while reading from or writing to the device.
    Io(io::Error),
    /// A device responded with an unexpected packet.
    Protocol(&'static str),
    /// A message we tried to send was too large to fit in 128 continuation packets.
    MessageTooLarge,
    /// The device stopped responding within the read timeout.
    Timeout,
}

impl From<io::Error> for HidrawError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CreationError> for HidrawError {
    fn from(_: CreationError) -> Self {
        Self::MessageTooLarge
    }
}

impl std::fmt::Display for HidrawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HidrawError::Io(e) => write!(f, "I/O error: {e}"),
            HidrawError::Protocol(s) => write!(f, "protocol error: {s}"),
            HidrawError::MessageTooLarge => {
                f.write_str("message too large to fit in CTAPHID frame")
            }
            HidrawError::Timeout => f.write_str("timed out waiting for response"),
        }
    }
}

impl std::error::Error for HidrawError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HidrawError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Enumerate `/dev/hidrawN` devices and return the subset that advertise the FIDO usage
/// page in their HID report descriptor. Devices that cannot be opened (e.g. due to udev
/// permissions) are skipped.
pub fn enumerate_fido_devices() -> io::Result<Vec<DeviceInfo>> {
    let mut enumerator = udev::Enumerator::new()?;
    enumerator.match_subsystem("hidraw")?;

    let mut devices = Vec::new();
    for device in enumerator.scan_devices()? {
        let Some(devnode) = device.devnode() else {
            continue;
        };
        let path = devnode.to_path_buf();

        let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
            // Most likely a permissions issue. Skip rather than surface to the caller.
            continue;
        };

        if !device_has_fido_usage(&file).unwrap_or(false) {
            continue;
        }

        let (vendor_id, product_id, name) = parent_hid_info(&device);
        devices.push(DeviceInfo {
            path,
            vendor_id,
            product_id,
            name,
        });
    }

    Ok(devices)
}

/// Pull VID/PID/name out of the parent `hid` device for a `hidraw` udev entry.
///
/// The `HID_ID` property is formatted as `BUS:VID:PID` in hex; the `HID_NAME` property
/// is a free-form human-readable string set by the kernel HID driver.
fn parent_hid_info(device: &udev::Device) -> (Option<u16>, Option<u16>, Option<String>) {
    let Some(parent) = device.parent_with_subsystem("hid").ok().flatten() else {
        return (None, None, None);
    };

    let hid_id = parent
        .property_value("HID_ID")
        .and_then(|s| s.to_str())
        .map(str::to_owned);
    let hid_name = parent
        .property_value("HID_NAME")
        .and_then(|s| s.to_str())
        .map(str::to_owned);

    let (vid, pid) = match hid_id.as_deref() {
        Some(s) => {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 3 {
                (
                    u16::from_str_radix(parts[1], 16).ok(),
                    u16::from_str_radix(parts[2], 16).ok(),
                )
            } else {
                (None, None)
            }
        }
        None => (None, None),
    };

    (vid, pid, hid_name)
}

/// Run the `HIDIOCGRDESC` ioctl against an open HIDRAW fd and look for the FIDO
/// usage page in the returned report descriptor.
fn device_has_fido_usage(file: &File) -> io::Result<bool> {
    let fd = file.as_raw_fd();

    let mut size: libc::c_int = 0;
    // SAFETY: `HIDIOCGRDESCSIZE` writes a single `int` through the supplied pointer.
    // `size` is a `c_int` that outlives the call.
    unsafe { ioctls::hidiocgrdescsize(fd, &mut size) }.map_err(io::Error::from)?;
    if size <= 0 {
        return Ok(false);
    }
    let Ok(size) = u32::try_from(size) else {
        return Ok(false);
    };
    let Ok(size_usize) = usize::try_from(size) else {
        return Ok(false);
    };
    if size_usize > HID_MAX_DESCRIPTOR_SIZE {
        return Ok(false);
    }

    let mut desc = ioctls::HidrawReportDescriptor {
        size,
        value: [0u8; HID_MAX_DESCRIPTOR_SIZE],
    };
    // SAFETY: `HIDIOCGRDESC` reads `desc.size` bytes into `desc.value`. We initialised
    // `desc.size` to the value returned by HIDIOCGRDESCSIZE above and bounded it
    // by HID_MAX_DESCRIPTOR_SIZE, so the kernel will not write past the buffer.
    unsafe { ioctls::hidiocgrdesc(fd, &mut desc) }.map_err(io::Error::from)?;

    Ok(report_descriptor_has_fido_usage(&desc.value[..size_usize]))
}

/// Walk an HID report descriptor and return whether it includes a `Usage Page (0xF1D0)` item.
fn report_descriptor_has_fido_usage(desc: &[u8]) -> bool {
    let Ok(descriptor) = hidparser::parse_report_descriptor(desc) else {
        // TODO: Should this return an error instead?
        return false;
    };
    if descriptor.input_reports.is_empty() {
        return false;
    }
    for report in descriptor.input_reports {
        for field in report.fields {
            let ReportField::Variable(v) = field else {
                continue;
            };
            if v.usage.page() == 0xF1D0 {
                return true;
            }
        }
    }
    false
}

mod ioctls {
    //! Linux HIDRAW ioctl bindings. See `include/uapi/linux/hidraw.h`.

    use nix::ioctl_read;

    /// `struct hidraw_report_descriptor` from `linux/hidraw.h`.
    #[repr(C)]
    pub struct HidrawReportDescriptor {
        pub size: u32,
        pub value: [u8; super::HID_MAX_DESCRIPTOR_SIZE],
    }

    // HIDIOCGRDESCSIZE: _IOR('H', 0x01, int)
    ioctl_read!(hidiocgrdescsize, b'H', 0x01, libc::c_int);
    // HIDIOCGRDESC: _IOR('H', 0x02, struct hidraw_report_descriptor)
    ioctl_read!(hidiocgrdesc, b'H', 0x02, HidrawReportDescriptor);
}

/// An async wrapper around an open `/dev/hidrawN` file descriptor.
///
/// Use [`HidDevice::open`] to obtain one, then either drive the CTAPHID protocol
/// directly with [`HidDevice::send`] / [`HidDevice::recv`], or call
/// [`HidDevice::init`] once after opening to perform the `CTAPHID_INIT` handshake
/// and obtain a per-application channel identifier.
pub struct HidDevice {
    fd: AsyncFd<OwnedFd>,
}

impl HidDevice {
    /// Open the given `/dev/hidrawN` path with `O_NONBLOCK | O_CLOEXEC` and wrap it
    /// in a [`tokio::io::unix::AsyncFd`] so subsequent reads/writes can be awaited.
    ///
    /// Must be called from within a Tokio runtime so the registration with the I/O
    /// driver can succeed.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let fd: OwnedFd = file.into();
        let fd = AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self { fd })
    }

    /// Write a single 64-byte CTAPHID packet to the device.
    ///
    /// The HIDRAW write interface requires a report-ID prefix byte. FIDO devices do not use
    /// numbered reports, so we always prepend `0x00` (as per [the HIDRAW
    /// docs](https://docs.kernel.org/hid/hidraw.html)), giving a 65-byte write.
    async fn write_packet(&self, packet: &[u8; MAX_PACKET_SIZE]) -> io::Result<()> {
        let mut framed = [0u8; MAX_PACKET_SIZE + 1];
        framed[1..].copy_from_slice(packet);

        let mut written = 0;
        while written < framed.len() {
            let mut guard = self.fd.writable().await?;
            let buf = &framed[written..];
            match guard.try_io(|inner| {
                // SAFETY: `inner.get_ref()` returns a reference to an owned fd that
                // outlives this call. `buf.as_ptr()` and `buf.len()` describe an
                // in-bounds region of `framed`.
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(usize::try_from(n).expect("non-negative isize should fit in usize"))
                }
            }) {
                Ok(Ok(n)) => {
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
                    }
                    written += n;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {
                    // Re-await the fd.
                }
            }
        }
        Ok(())
    }

    /// Read a single 64-byte CTAPHID packet from the device.
    ///
    /// Returns an error if the device returns fewer than 64 bytes; CTAPHID requires
    /// every packet to be exactly that size.
    async fn read_packet(&self) -> io::Result<[u8; MAX_PACKET_SIZE]> {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        // This loop is necessary in the case that try_io fails with a WouldBlock erorr.
        // try_io should succeed only once, and return the full 64 bytes.
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                // SAFETY: `inner.get_ref()` returns a reference to an owned fd that
                // outlives this call. `buf.as_mut_ptr()` and `buf.len()` describe an
                // in-bounds region of `buf`.
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(usize::try_from(n).unwrap_or(0))
                }
            }) {
                Ok(Ok(n)) => {
                    if n != MAX_PACKET_SIZE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "HID report had unexpected size: got {n} bytes, expected {MAX_PACKET_SIZE}"
                            ),
                        ));
                    }
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {
                    // Re-await fd.
                }
            }
        }
    }

    /// Send a CTAPHID [`Message`], breaking it up into wire packets and writing them
    /// in sequence.
    pub async fn send(&self, message: &Message) -> Result<(), HidrawError> {
        // We use `message.encode_packets()` here instead of the `Message::send` implementation
        // because (1) `self.fd` doesn't implement `std::io::Write`, and (2) we need to add the
        // zero byte at the beginning of each packet for HIDRAW.
        for packet in message.encode_packets() {
            self.write_packet(&packet).await?;
        }
        Ok(())
    }

    /// Receive a single CTAPHID [`Message`] on the given channel.
    ///
    /// `KEEPALIVE` packets are dropped: per CTAPHID, they do not constitute a
    /// response and may arrive at least every 100 ms while the authenticator
    /// processes a long-running request such as user verification.
    pub async fn recv(&self, channel: u32) -> Result<Message, HidrawError> {
        // Here we use `hid::ChannelHandler`, which uses a hashmap internally to support messages
        // being sent on multiple channels. Since we really only care about one channel, we could
        // replace this with a simpler implementation that just ignores all packets sent to a
        // different channel (which is effectively what we do here).
        let mut handler = ChannelHandler::default();
        loop {
            let packet = match timeout(PACKET_READ_TIMEOUT, self.read_packet()).await {
                Ok(res) => res?,
                Err(_) => return Err(HidrawError::Timeout),
            };

            let Some(message) = handler.handle_packet(&packet) else {
                continue;
            };

            if message.channel != channel {
                // Stale packet for another channel — drop and keep waiting.
                continue;
            }
            if matches!(message.command, Command::KeepAlive) {
                continue;
            }
            return Ok(message);
        }
    }

    /// Perform the `CTAPHID_INIT` handshake against the device and return the
    /// allocated channel identifier.
    pub async fn init(&self) -> Result<InitResponse, HidrawError> {
        let nonce = {
            let mut buf = [0u8; 8];
            let mut rng: ChaCha20Rng = rand::make_rng();
            rng.fill_bytes(&mut buf);
            buf
        };

        let request = Message::new(BROADCAST_CID, Command::Init, &nonce)?;
        self.send(&request).await?;

        let response = self.recv(BROADCAST_CID).await?;
        if !matches!(response.command, Command::Init) {
            return Err(HidrawError::Protocol(
                "unexpected command in CTAPHID_INIT response",
            ));
        }
        // Payload layout:
        // 8 bytes nonce
        // 4 bytes channel ID
        // 1 byte protocol version,
        // 1 byte major device version number
        // 1 byte minor device version number
        // 1 byte build device version number
        // 1 byte capabilities flags.
        if response.payload.len() < 17 {
            return Err(HidrawError::Protocol("short CTAPHID_INIT response payload"));
        }
        if response.payload[..8] != nonce {
            return Err(HidrawError::Protocol(
                "CTAPHID_INIT response nonce mismatch",
            ));
        }
        // Multi-byte fields must be specified in little endian order, per the HID specification.
        let cid = u32::from_le_bytes([
            response.payload[8],
            response.payload[9],
            response.payload[10],
            response.payload[11],
        ]);
        Ok(InitResponse {
            channel: cid,
            protocol_version: response.payload[12],
            device_version_major: response.payload[13],
            device_version_minor: response.payload[14],
            device_version_build: response.payload[15],
            capabilities: Capabilities::from_bits(response.payload[16]),
        })
    }
}

/// Successful response payload from `CTAPHID_INIT`.
#[derive(Debug, Clone)]
pub struct InitResponse {
    /// The freshly allocated 4-byte channel identifier to use for subsequent transactions.
    pub channel: u32,
    /// CTAPHID protocol version implemented by the authenticator.
    pub protocol_version: u8,
    /// Vendor-defined major device version.
    pub device_version_major: u8,
    /// Vendor-defined minor device version.
    pub device_version_minor: u8,
    /// Vendor-defined build version.
    pub device_version_build: u8,
    /// Reported capabilities bit-field; see [`Capabilities`].
    pub capabilities: Capabilities,
}

/// Capabilities reported in the `CTAPHID_INIT` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(u8);

impl Capabilities {
    /// Implements the `CTAPHID_WINK` command.
    pub const WINK: u8 = 0x01;
    /// Implements the `CTAPHID_CBOR` command.
    pub const CBOR: u8 = 0x04;
    /// Does NOT implement `CTAPHID_MSG` (i.e. no U2F/CTAP1 fallback).
    pub const NMSG: u8 = 0x08;

    /// Build a `Capabilities` value from the raw byte in the `CTAPHID_INIT` response.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Whether the device implements `CTAPHID_CBOR`.
    pub const fn supports_cbor(self) -> bool {
        self.0 & Self::CBOR != 0
    }

    /// Whether the device implements `CTAPHID_WINK`.
    pub const fn supports_wink(self) -> bool {
        self.0 & Self::WINK != 0
    }

    /// Whether the device explicitly does NOT implement `CTAPHID_MSG`.
    pub const fn no_msg(self) -> bool {
        self.0 & Self::NMSG != 0
    }

    /// Raw capability bits, as reported by the authenticator.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_fido_usage_in_yubikey_style_descriptor() {
        // A minimal HID report descriptor that declares a top-level FIDO collection,
        // similar to what a YubiKey reports.
        let desc: [u8; 34] = [
            0x06, 0xD0, 0xF1, // Usage Page (0xF1D0)
            0x09, 0x01, // Usage (0x01)
            0xA1, 0x01, // Collection (Application)
            0x09, 0x20, // Usage (FIDO_USAGE_DATA_IN)
            0x15, 0x00, // Logical Minimum (0)
            0x26, 0xFF, 0x00, // Logical Maximum (255)
            0x75, 0x08, // Report Size (8)
            0x95, 0x40, // Report Count (64)
            0x81, 0x02, // Input (Data,Var,Abs)
            0x09, 0x21, // Usage (FIDO_USAGE_DATA_OUT)
            0x15, 0x00, // Logical Minimum (0)
            0x26, 0xFF, 0x00, // Logical Maximum (255)
            0x75, 0x08, // Report Size (8)
            0x95, 0x40, // Report Count (64)
            0x91, 0x02, // Output (Data,Var,Abs)
            0xC0, // End Collection
        ];
        assert!(report_descriptor_has_fido_usage(&desc));
    }

    #[test]
    fn rejects_keyboard_descriptor() {
        // A trimmed-down keyboard report descriptor with Usage Page (Generic Desktop).
        let desc: [u8; 8] = [
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x06, // Usage (Keyboard)
            0xA1, 0x01, // Collection (Application)
            0xC0, 0x00, // End collection + padding
        ];
        assert!(!report_descriptor_has_fido_usage(&desc));
    }

    #[test]
    fn handles_empty_descriptor() {
        assert!(!report_descriptor_has_fido_usage(&[]));
    }

    #[test]
    fn handles_truncated_usage_page_item() {
        // 0x06 declares a 2-byte usage page value but only 1 byte follows.
        // The parser must not panic.
        let desc: [u8; 2] = [0x06, 0xD0];
        assert!(!report_descriptor_has_fido_usage(&desc));
    }
}
