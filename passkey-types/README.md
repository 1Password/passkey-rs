# Passkey Types

[![github path](https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--types-informational?logo=github&style=flat)](https://github.com/1Password/passkey-rs/tree/main/passkey-types)
[![Crates.io version](https://img.shields.io/crates/v/passkey-types?logo=rust&style=flat)](https://crates.io/crates/passkey-types)
[![crate documentation](https://img.shields.io/docsrs/passkey-types/latest?logo=docs.rs&style=flat)](https://docs.rs/passkey-types/)

This crate contains the types defined in both the [WebAuthn Level 3] and [CTAP 2.0] specifications for the operations they define. They are each seperated in their own modules.

## Webauthn

In this module the type names mirror exactly those in the specifications for ease of navigation. They are defined in a way that allows interoperability with the web types directly as well as the [JSON encoding] for over network communication.

## CTAP 2

In this module, seeing as the method inputs are not given explicit names, the `Request` and `Response` types are defined in seperate modules for each operation. These types make use of the same data structures from the [WebAuthn](#webauthn) module. In some cases though, the types have different constraits regarding required and optional fields, in which case it is re-defined in the [CTAP](#ctap-2) module along with a `TryFrom` implementation in either direction.


[WebAuthn Level 3]: https://w3c.github.io/webauthn/
[CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
[JSON encoding]: https://w3c.github.io/webauthn/#typedefdef-publickeycredentialjson