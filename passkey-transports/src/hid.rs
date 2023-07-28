//! <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb>
use std::collections::HashMap;

/// The CTAPHID protocol implements the following commands.
#[derive(Debug, Clone, Copy)]
pub enum Command {
    /// This command sends an encapsulated CTAP1/U2F message to the device. The semantics of the
    /// data message is defined in the U2F Raw Message Format encoding specification. See [passkey-rs::u2f].
    Msg = 0x03,
    /// This command sends an encapsulated CTAP CBOR encoded message. The semantics of the data
    /// message is defined in the CTAP Message encoding specification. Please note that keep-alive
    /// messages MAY be sent from the device to the client before the response message is returned.
    Cbor = 0x10,
    /// This command has two functions.
    ///
    /// If sent on an allocated CID, it synchronizes a channel, discarding the current transaction,
    /// buffers and state as quickly as possible. It will then be ready for a new transaction. The
    /// device then responds with the CID of the channel it received the INIT on, using that channel.
    ///
    /// If sent on the broadcast CID, it requests the device to allocate a unique 32-bit channel
    /// identifier (CID) that can be used by the requesting application during its lifetime.
    /// The requesting application generates a nonce that is used to match the response. When the
    /// response is received, the application compares the sent nonce with the received one.
    /// After a positive match, the application stores the received channel id and uses that for
    /// subsequent transactions.
    ///
    /// To allocate a new channel, the requesting application SHALL use the broadcast channel
    /// CTAPHID_BROADCAST_CID (0xFFFFFFFF). The device then responds with the newly allocated
    /// channel in the response, using the broadcast channel.
    Init = 0x06,
    /// Sends a transaction to the device, which immediately echoes the same data back. This
    /// command is defined to be a uniform function for debugging, latency and performance measurements.
    Ping = 0x01,
    /// Cancel any outstanding requests on this CID. If there is an outstanding request that can be
    /// cancelled, the authenticator MUST cancel it and that cancelled request will reply with the
    /// error CTAP2_ERR_KEEPALIVE_CANCEL.
    ///
    /// As the CTAPHID_CANCEL command is sent during an ongoing transaction, transaction semantics
    /// do not apply. Whether a request was cancelled or not, the authenticator MUST NOT reply to
    /// the CTAPHID_CANCEL message itself. The CTAPHID_CANCEL command MAY be sent by the client
    /// during ongoing processing of a CTAPHID_CBOR request. The CTAP2_ERR_KEEPALIVE_CANCEL response
    /// MUST be the response to that request, not an error response in the HID transport.
    ///
    /// A CTAPHID_CANCEL received while no CTAPHID_CBOR request is being processed, or on a
    /// non-active CID SHALL be ignored by the authenticator.
    Cancel = 0x11,
    /// This command code is used in response messages only.
    Err = 0x3F,
    /// This command code is sent while processing a CTAPHID_MSG. It should be sent at least every 100ms
    /// and whenever the status changes. A KEEPALIVE sent by an authenticator does not constitute a
    /// response and does therefore not end an ongoing transaction.
    KeepAlive = 0x3B,

    // Optional Commands:
    //---------------------------------------------------------------------------------------------
    /// The wink command performs a vendor-defined action that provides some visual or audible
    /// identification a particular authenticator. A typical implementation will do a short burst
    /// of flashes with a LED or something similar. This is useful when more than one device is
    /// attached to a computer and there is confusion which device is paired with which connection.
    Wink = 0x08,
    /// The lock command places an exclusive lock for one channel to communicate with the device.
    /// As long as the lock is active, any other channel trying to send a message will fail. In
    /// order to prevent a stalling or crashing application to lock the device indefinitely, a lock
    /// time up to 10 seconds may be set. An application requiring a longer lock has to send
    /// repeating lock commands to maintain the lock.
    Lock = 0x04,
}

/// These are used in [Command::Err] only as response when an error is encountered
pub enum ErrorCode {
    /// The command in the request is invalid
    InvalidCmd = 0x01,
    /// The parameter(s) in the request is invalid
    InvalidPar = 0x02,
    /// The length field (BCNT) is invalid for the request
    InvalidLen = 0x03,
    /// The sequence does not match expected value
    InvalidSeq = 0x04,
    /// The message has timed out
    MsgTimeout = 0x05,
    /// The device is busy for the requesting channel. The client SHOULD retry the request after a
    /// short delay. Note that the client may abort the transaction if the command is no longer
    /// relevant.
    ChannelBusy = 0x06,
    /// Command requires channel lock
    LockRequired = 0x0A,
    /// CID is not valid.
    InvalidChannel = 0x0B,
    /// Unspecified error
    Other = 0x7F,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x03 => Self::Msg,
            0x10 => Self::Cbor,
            0x06 => Self::Init,
            0x01 => Self::Ping,
            0x11 => Self::Cancel,
            0x3F => Self::Err,
            0x3B => Self::KeepAlive,
            0x08 => Self::Wink,
            0x04 => Self::Lock,
            _ => return Err(()),
        })
    }
}

/// Byte used as mask to enable and disable the 7th bit for the command byte. This bit is used to
/// distinguish between the Initial Packet and any subsequent continuation packets.
const PACKET_DISCRIPTOR_BIT: u8 = 1 << 7;

impl Command {
    /// Encodes a command to its byte representation on the wire with the 7th bit always on.
    #[allow(clippy::as_conversions)]
    pub fn encode(self) -> u8 {
        PACKET_DISCRIPTOR_BIT | self as u8
    }
}
/// a CTAP2 HID packet can be at most 64 bytes, bigger messages are broken up using Continuation Packets
const MAX_PACKET_SIZE: usize = 64;

/// Initialization Packet header
///
/// It can be distinguished from a [ContHeader] with bit 7 from the command identifier bit.
#[derive(Debug)]
struct InitHeader {
    /// Channel Identifier, represented in big endian
    channel: u32,
    /// Command Identifier, bit 7 is always set
    command: Command,
    /// Payload length reprensented as a u16 in big endian, value may be longer than the payload in this packet
    payload_len: usize,
}

impl InitHeader {
    const HEADER_SIZE: usize = 7;
    const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - Self::HEADER_SIZE;

    /// Try parsing a packet as a Initial packet, returning a parse header with the payload data
    // TODO: Use actual error types
    fn try_from(channel: u32, data: &[u8]) -> Result<(Self, &[u8]), ()> {
        const REST_HEADER_SIZE: usize = InitHeader::HEADER_SIZE - 4;
        if data.len() < REST_HEADER_SIZE {
            return Err(());
        }

        let (cmd_byte, data) = data.split_at(1);
        // Extract the command bit and unset the 7th bit.
        let cmd_byte = cmd_byte[0] & !PACKET_DISCRIPTOR_BIT;
        let command = cmd_byte.try_into()?;

        let (payload_len_bytes, data) = data.split_at(2);

        let payload_len = u16::from_be_bytes(payload_len_bytes.try_into().unwrap()).into();
        let data = if payload_len > Self::MAX_PAYLOAD_SIZE {
            data
        } else {
            &data[..payload_len]
        };
        Ok((
            Self {
                channel,
                command,
                payload_len,
            },
            data,
        ))
    }

    /// Encode the header into the re-usable packet buffer.
    fn encode(self, buf: &mut [u8]) {
        buf[..4].copy_from_slice(&self.channel.to_ne_bytes());
        buf[4] = self.command.encode();

        // SAFETY: only Message can programatically create new headers, and its payload length is
        // validated in Message::new. So this unwrap can never panic.
        buf[5..7].copy_from_slice(&u16::try_from(self.payload_len).unwrap().to_be_bytes())
    }
}

/// Continuation Packet
///
/// It can be distinguished from a `InitPacket` with bit 7 from the packet sequence bit.
#[derive(Debug)]
struct ContHeader {
    /// Channel Identifier, represented in big endian
    channel: u32,
    /// Packet Sequence can be of value `0x00..=0x7f` because bit 7 is always cleared.
    seq: u8,
}

impl ContHeader {
    const HEADER_SIZE: usize = 5;
    const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - Self::HEADER_SIZE;

    /// Parse a packet as a Continuation Packet returning the header and associated payload.
    ///
    /// Warning: The size of the payload cannot be known by the packet alone and must use the length
    /// parsed from the Initial Packet along with all the data received from previous continuation
    /// packets.
    fn from(channel: u32, data: &[u8]) -> (Self, &[u8]) {
        let seq = data[0];
        (Self { channel, seq }, &data[1..])
    }

    /// Encode the header in binary format into the re-usable packet buffer.
    fn encode(self, buf: &mut [u8]) {
        buf[..4].copy_from_slice(&self.channel.to_ne_bytes());
        buf[4] = self.seq;
    }
}

/// A generic CTAP2 HID packet
#[derive(Debug)]
enum PacketHeader {
    /// Initial packet sent can be standalone or followed by continuation packets.
    Initialization(InitHeader),
    /// Continuation packet for payloads that are larger than the allowable packet size.
    Continuation(ContHeader),
}

impl PacketHeader {
    /// Try parsing a byte buffer into a CTAP2 HID packet with its associated data payload.
    // TODO: return actual error type
    fn try_from(data: &[u8]) -> Result<(Self, &[u8]), ()> {
        // must be at least the length of a continuation header
        if data.len() < ContHeader::HEADER_SIZE {
            return Err(());
        }
        let (channel_bytes, data) = data.split_at(4);

        // SAFETY: guaranteed to be 4 bytes due to check and split above
        let channel = u32::from_ne_bytes(channel_bytes.try_into().unwrap());
        let cmd_or_seq_bit = data[0];
        // mask all bits except the 7th bit
        let is_cmd_or_seq = cmd_or_seq_bit & PACKET_DISCRIPTOR_BIT;

        // If the 7th bit is set, then this equality will return true and this would be an
        // initialization packet. otherwise, bit 7 is not set and thus this packet is a continuation
        // packet.
        let packet = if is_cmd_or_seq == PACKET_DISCRIPTOR_BIT {
            let (header, data) = InitHeader::try_from(channel, data)?;
            (Self::Initialization(header), data)
        } else {
            let (header, data) = ContHeader::from(channel, data);
            (Self::Continuation(header), data)
        };
        Ok(packet)
    }

    /// Encode the packet header and associated data into the re-usable packet buffer.
    fn encode(self, data: &[u8], buf: &mut [u8; MAX_PACKET_SIZE]) {
        match self {
            PacketHeader::Initialization(init) => {
                init.encode(buf);
                let data_len = if data.len() < InitHeader::MAX_PAYLOAD_SIZE {
                    data.len()
                } else {
                    InitHeader::MAX_PAYLOAD_SIZE
                } + InitHeader::HEADER_SIZE;
                buf[InitHeader::HEADER_SIZE..data_len].copy_from_slice(data)
            }
            PacketHeader::Continuation(cont) => {
                cont.encode(buf);
                let data_len = if data.len() < ContHeader::MAX_PAYLOAD_SIZE {
                    data.len()
                } else {
                    ContHeader::MAX_PAYLOAD_SIZE
                } + ContHeader::HEADER_SIZE;
                buf[ContHeader::HEADER_SIZE..data_len].copy_from_slice(data)
            }
        }
    }

    /// Get the length of the header size
    const fn len(&self) -> usize {
        match self {
            PacketHeader::Initialization(_) => InitHeader::HEADER_SIZE,
            PacketHeader::Continuation(_) => ContHeader::HEADER_SIZE,
        }
    }
}

/// A complete CTAP2 message, which is built from one or many packets.
///
/// The initial packet is an `InitPacket` then multiple `ContPacket` are used to populate a large
/// payload which is larger than the maximum packet size.
#[derive(Debug)]
pub struct Message {
    /// Channel Identifier. This is 4 bytes, but the endianness is not defined by the spec hence we
    /// will simply use the native endianness since its actual value is just important on the wire.
    pub channel: u32,
    /// Command identifier. This comes from the `InitPacket`.
    pub command: Command,
    /// Total number of continuation packets used to create this message. Used for internal state.
    pub sequence: u8,
    /// Total Payload length. This is represented as a Big Endian u16 on the wire.
    pub payload_len: usize,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

/// Error when trying to extend a message from a newly recieved Continuation packet.
#[derive(Debug)]
enum ExtensionError {
    /// Packet was received out of sequence
    OutOfSequence,
    /// Packet is not of the same channel ID as the current message
    WrongChannel,
}

/// Error occuring when trying to create a new message to send to a client
#[derive(Debug)]
pub enum CreationError {
    /// Occurs when the data to send is too big to be sent in the alloted Initial Packet and 128
    /// possible continuation packets.
    PayloadTooBig,
}

impl Message {
    /// Create a new message for the given channel of the given command type with the data payload.
    pub fn new(channel: u32, command: Command, data: &[u8]) -> Result<Self, CreationError> {
        if data.len() > u16::MAX.into() {
            return Err(CreationError::PayloadTooBig);
        }
        let rest = data.len().saturating_sub(InitHeader::MAX_PAYLOAD_SIZE);
        // +1 in case of the being a last packet that is not full
        if rest > 0 && rest / ContHeader::MAX_PAYLOAD_SIZE + 1 > 128 {
            return Err(CreationError::PayloadTooBig);
        }
        Ok(Self {
            channel,
            command,
            sequence: 0,
            payload_len: data.len(),
            payload: data.to_vec(),
        })
    }

    /// Send a message to the client by breaking it up into CTAP2 HID packets and sending them in sequence.
    pub fn send<W: std::io::Write>(self, writer: &mut W) -> Result<(), std::io::Error> {
        let packets = self.to_packets();
        let mut buf = [0; MAX_PACKET_SIZE];
        let num_packets = packets.len() - 1;
        for (i, (header, data)) in packets.into_iter().enumerate() {
            // if last packet zero bytes that will not be written to
            if i == num_packets {
                let data_len = header.len() + data.len();
                buf[data_len..].iter_mut().for_each(|b| *b = 0);
            }
            header.encode(data, &mut buf);

            let _ = writer.write(&buf)?;
            writer.flush()?;
        }
        Ok(())
    }

    /// Break up a [Message] into packets which are a tuple of the packet's header and its associated
    /// payload of appropriate length.
    ///
    /// The reason this method does not consume `self` is because it re-uses the payload's `Vec` for
    /// the slices of all the packet payloads.
    fn to_packets(&self) -> Vec<(PacketHeader, &[u8])> {
        let init_header = PacketHeader::Initialization(InitHeader {
            channel: self.channel,
            command: self.command,
            payload_len: self.payload_len,
        });
        let packets = if self.payload_len <= InitHeader::MAX_PAYLOAD_SIZE {
            vec![(init_header, self.payload.as_slice())]
        } else {
            [(init_header, &self.payload[..InitHeader::MAX_PAYLOAD_SIZE])]
                .into_iter()
                .chain(
                    self.payload[InitHeader::MAX_PAYLOAD_SIZE..]
                        .chunks(ContHeader::MAX_PAYLOAD_SIZE)
                        .enumerate()
                        .map(|(seq, payload)| {
                            (
                                PacketHeader::Continuation(ContHeader {
                                    channel: self.channel,
                                    // Safety: Validated by Message::new that this cannot be greater than 128
                                    seq: seq.try_into().unwrap(),
                                }),
                                payload,
                            )
                        }),
                )
                .collect()
        };

        packets
    }

    /// Initialize a Message from an Initialization Packet
    fn init(header: InitHeader, data: &[u8]) -> Self {
        Self {
            channel: header.channel,
            command: header.command,
            sequence: 0,
            payload_len: header.payload_len,
            payload: data.to_vec(),
        }
    }

    /// Check if all packets associated with this message have been received.
    fn is_complete(&self) -> bool {
        self.payload_len == self.payload.len()
    }

    /// Extend a message with a continuation packet.
    ///
    /// If extension is successful, returns a bool indicating whether the message is complete.
    /// Returns an error if continuation packet is not of the same channel or if the sequence is wrong.
    fn extend(&mut self, header: ContHeader, data: &[u8]) -> Result<bool, ExtensionError> {
        if self.channel != header.channel {
            return Err(ExtensionError::WrongChannel);
        }

        if header.seq == self.sequence {
            self.sequence += 1;
            let remaining_bytes = self.payload_len - self.payload.len();
            const MAX_CONT_PACKET_LEN: usize = MAX_PACKET_SIZE - ContHeader::HEADER_SIZE;
            if remaining_bytes <= MAX_CONT_PACKET_LEN {
                self.payload.extend_from_slice(&data[..remaining_bytes]);
                Ok(true)
            } else {
                self.payload.extend_from_slice(data);
                Ok(false)
            }
        } else {
            Err(ExtensionError::OutOfSequence)
        }
    }
}

/// Handles the receiving of packets and saves the messages according to their channels.
#[derive(Default)]
pub struct ChannelHandler {
    channels: HashMap<u32, Message>,
}

impl ChannelHandler {
    /// Handle a new data packet and returns the associated message if it is complete and all its
    /// associated packets have been received.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Option<Message> {
        let (header, payload) = PacketHeader::try_from(packet).ok()?;
        match header {
            PacketHeader::Initialization(init) => {
                let channel = init.channel;
                let message = Message::init(init, payload);
                if message.is_complete() {
                    Some(message)
                } else {
                    // In the unlikely event this channel was reused and there was an unfinished
                    // message, just drop it.
                    let _ = self.channels.insert(channel, message);
                    None
                }
            }
            PacketHeader::Continuation(cont) => {
                let channel = cont.channel;
                // short circuit if this is a continuation packet of a message which we never got
                // the init packet.
                let message = self.channels.get_mut(&channel)?;
                if message.extend(cont, payload).ok()? {
                    self.channels.remove(&channel)
                } else {
                    None
                }
            }
        }
    }
}
