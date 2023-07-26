# Passkey Client

[![github]](https://github.com/1Password/passkey-rs/tree/main/passkey-client)
[![version]](https://crates.io/crates/passkey-client)
[![documentation]](https://docs.rs/passkey-client/)

This crate defines a `Client` type along with a basic implementation of the [Webauthn]
specification. The `Client` uses an `Authenticator` to perform the actual cryptographic
operations, while the Client itself marshals data to and from the structs received from the Relying Party.

This crate does not provide any code to perform networking requests to and from Relying Parties.

[github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--client-informational?logo=github&style=flat
[version]: https://img.shields.io/crates/v/passkey-client?logo=rust&style=flat
[documentation]: https://img.shields.io/docsrs/passkey-client/latest?logo=docs.rs&style=flat
[Webauthn]: https://w3c.github.io/webauthn/