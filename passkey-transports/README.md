# Passkey Transports

[![github]](https://github.com/1Password/passkey-rs/tree/main/passkey-transports)
[![version]](https://crates.io/crates/passkey-transports)
[![documentation]](https://docs.rs/passkey-transports/)

This crate implements the CTAP2 transports between the client and the authenticator. The direction is from the perspective of the client. This is used in the case when the authenticator is not internal to the client's program but accessible as another process or device.

Currently only the USB HID transport is implemented with plans to support the other specified transports as well as the different platform authenticators.


[github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--transports-informational?logo=github&style=flat
[version]: https://img.shields.io/crates/v/passkey-transports?logo=rust&style=flat
[documentation]: https://img.shields.io/docsrs/passkey-transports/latest?logo=docs.rs&style=flat
[Webauthn]: https://w3c.github.io/webauthn/