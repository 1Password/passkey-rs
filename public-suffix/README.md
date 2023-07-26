# public-suffix by 1Password

[![github]](https://github.com/1Password/passkey-rs/tree/main/public-suffix)
[![version]](https://crates.io/crates/public-suffix/)
[![documentation]](https://docs.rs/public-suffix/)

The `public-suffix` crate provides a compact and efficient way to determine the effective TLD-plus-one of any given domain.

This crate is driven by a data file, held in `public-suffix-list.dat` and contains code to generate Rust structures to represent this information in code.

## Using this Crate

You can use this crate directly, using the included `DEFAULT_PROVIDER` list as follows:

```
let domain = "sainsburys.co.uk";
let etld = DEFAULT_PROVIDER.effective_tld_plus_one(domain);
```

## Generating a Custom Public Suffix List

It may be that users of this crate wish to compute eTLD+1 differently for certain domains according to the needs of their particular application.

To do this, provide your own version of `public_suffix_list.dat` and run the included generator script (`gen.sh`) with the contents of your custom TLD file.

This will regenerate the Rust representations of that data for inclusion in your own crate. The `main.go` program called by `gen.sh` supports various arguments to control its output. The main arguments you may wish to use are:

- `--output-path` - directory in which to place the generated files.
- `--base-name` - the base name of the generated files. The generator will create `${base-name}.rs` and `${base-name}_test.rs` in the directory specified by `output-path`.
- `--struct` - the name of the Rust struct that will be generated to represent your custom TLD data.
- `--crate` - a boolean controlling whether the struct will be created as `public_suffix::StructName` (if true) or `crate::StructName` (if false). When you are creating your own structs, always set this to false.

## Using Your Custom Public Suffix List

Next, in your `Cargo.toml`, disable the `default-provider` feature in this crate: `default-features = false`. Doing so will remove the built-in implementation of the public suffix list structure and instead you can use your own:

```
type PublicSuffixList = ListProvider<my_custom_tld_list::MyCustomTldListStruct>;

pub const MY_CUSTOM_TLD_LIST: PublicSuffixList = PublicSuffixList::new();
```

...then you can call the same functions on `MY_CUSTOM_TLD_LIST`:

```
let domain = "sainsburys.co.uk";
let etld = MY_CUSTOM_TLD_LIST.effective_tld_plus_one(domain);
```

## Contributing and feedback

`public-suffix` is an [open source project](https://github.com/1Password/public-suffix).

🐛 If you find an issue you'd like to report, or otherwise have feedback, please [file a new Issue](https://github.com/1Password/public-suffix/issues/new).

🧑‍💻 If you'd like to contribute to the code please start by filing or commenting on an [Issue](https://github.com/1Password/public-suffix/issues) so we can track the work.

## Credits

Made with ❤️ and ☕ by the [1Password](https://1password.com/) team.

### Get a free 1Password account for your open source project

Does your team need a secure way to manage passwords and other credentials for your open source project? Head on over to our [other repository](https://github.com/1Password/1password-teams-open-source) to get a 1Password Teams account on us:

✨[1Password for Open Source Projects](https://github.com/1Password/1password-teams-open-source)

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>


[github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpublic--suffix-informational?logo=github&style=flat
[version]: https://img.shields.io/crates/v/public-suffix?logo=rust&style=flat
[documentation]: https://img.shields.io/docsrs/public-suffix/latest?logo=docs.rs&style=flat