# Passkey Authenticator

[![github]](https://github.com/1Password/passkey-rs/tree/main/passkey-authenticator)
[![version]](https://crates.io/crates/passkey-authenticator)
[![documentation]](https://docs.rs/passkey-authenticator/)

This crate defines an Authenticator type along with a basic implementation of the [CTAP 2.0] specification. The `Authenticator` struct is designed in such a way that storage and user interaction are defined through traits, allowing only the parts that vary between vendors, but keeping the specification compliant implementation regardless of vendor. This is why the `Ctap2Api` trait is sealed, to prevent external implementations.

[github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--authenticator-informational?logo=github&style=flat
[version]: https://img.shields.io/crates/v/passkey-authenticator?logo=rust&style=flat
[documentation]: https://img.shields.io/docsrs/passkey-authenticator/latest?logo=docs.rs&style=flat
[CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html

## Why RustCrypto?

For targeting WASM, yes there are other cryptographic libraries out there that allow targeting WASM, but none of them are as easy to compile to wasm than the pure rust implementations of the [RustCrypto] libraries. Now this does come with limitations, so there are plans to provide a similar backing trait to "plug-in" the desired cryptography from a vendor. Work is ongoing for this.

[RustCrypto]: https://github.com/RustCrypto
