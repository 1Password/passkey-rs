#![allow(clippy::as_conversions)]
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The Rust code in this file is mostly a transliteration of list.go and
// list_test.go.

//! # About
//!
//! public-suffix provides a public suffix list based on data from
//! <https://publicsuffix.org/>.
//!
//!
//! A public suffix is one under which Internet users can directly register
//! names. It is related to, but different from, a TLD (top level domain).
//!
//! "com" is a TLD (top level domain). Top level means it has no dots.
//!
//! "com" is also a public suffix. Amazon and Google have registered different
//! siblings under that domain: "amazon.com" and "google.com".
//!
//! "au" is another TLD, again because it has no dots. But it's not "amazon.au".
//! Instead, it's "amazon.com.au".
//!
//! "com.au" isn't an actual TLD, because it's not at the top level (it has
//! dots). But it is an eTLD (effective TLD), because that's the branching point
//! for domain name registrars.
//!
//! Another name for "an eTLD" is "a public suffix". Often, what's more of
//! interest is the eTLD+1, or one more label than the public suffix. For
//! example, browsers partition read/write access to HTTP cookies according to
//! the eTLD+1. Web pages served from "amazon.com.au" can't read cookies from
//! "google.com.au", but web pages served from "maps.google.com" can share
//! cookies from "www.google.com", so you don't have to sign into Google Maps
//! separately from signing into Google Web Search. Note that all four of those
//! domains have 3 labels and 2 dots. The first two domains are each an eTLD+1,
//! the last two are not (but share the same eTLD+1: "google.com").
//!
//! All of these domains have the same eTLD+1:
//!  - "www.books.amazon.co.uk"
//!  - "books.amazon.co.uk"
//!  - "amazon.co.uk"
//! Specifically, the eTLD+1 is "amazon.co.uk", because the eTLD is "co.uk".
//!
//! ```
//! use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider, Error};
//!
//! assert_eq!(
//!     DEFAULT_PROVIDER.effective_tld_plus_one("www.books.amazon.com.au"),
//!     Ok("amazon.com.au")
//! );
//! assert_eq!(
//!     DEFAULT_PROVIDER.effective_tld_plus_one("books.amazon.com.au"),
//!     Ok("amazon.com.au")
//! );
//! assert_eq!(
//!     DEFAULT_PROVIDER.effective_tld_plus_one("amazon.com.au"),
//!     Ok("amazon.com.au")
//! );
//! assert_eq!(
//!     DEFAULT_PROVIDER.effective_tld_plus_one("com.au"),
//!     Err(Error::CannotDeriveETldPlus1)
//! );
//! assert_eq!(
//!     DEFAULT_PROVIDER.effective_tld_plus_one("au"),
//!     Err(Error::CannotDeriveETldPlus1)
//! );
//! ```
//!
//! There is no closed form algorithm to calculate the eTLD of a domain.
//! Instead, the calculation is data driven. This package provides a
//! pre-compiled snapshot of Mozilla's PSL (Public Suffix List) data at
//! <https://publicsuffix.org/>
//!
//! # `default_provider` Feature and Custom TLD Lists
//!
//! This crate comes with a version of the Mozilla Public Suffix List built in.
//! This is controlled by a crate feature called `default_provider` which is
//! enabled by default. Disabling this feature removes the provided TLD list from
//! the compiled binary, potentially saving some size, and allows the user to provide
//! their own. See the documentation for [ListProvider] and [Table] for more details.
//!
//! # Updating to the latest version of the Public Suffix List:
//!
//! 0. Make sure you have golang installed.
//! 1. Make the public-suffix crate the current working directory.
//! 2. `wget https://publicsuffix.org/list/public_suffix_list.dat`, which will
//! overwrite the old version of this file.
//! 3. Run `./gen.sh` to regenerate the list from the updated `public_suffix_list.dat`.
//! The first time you run this, you'll need network connectivity to `go get` the
//! dependencies.
//! 4. Commit the changed generated source code and the updated
//! `public_suffix_list.dat`.
//!
//! We intentionally do not try to download the latest version of the public suffix
//! list during the build to keep the build deterministic and networking-free.
//!
//! We'd like to avoid checking in the Rust source code generated from
//! `public_suffix_list.dat`, but we don't want the build to depend on the Go
//! compiler.

mod tld_list;
mod types;

#[cfg(test)]
mod tld_list_test;

use std::{marker::PhantomData, ops::RangeFrom};
pub use types::Table;

#[cfg(feature = "default_provider")]
use tld_list::*;

#[cfg(feature = "default_provider")]
/// This type is provided as part of the `default_provider` feature as a concrete
/// instantiation of ListProvider using this crate's default TLD list.
pub type PublicSuffixList = ListProvider<TLDList>;

#[cfg(feature = "default_provider")]
/// DEFAULT_PROVIDER provides a default instance of ListProvider that provides results
/// based on the standard Mozilla Public Suffix List.
pub const DEFAULT_PROVIDER: PublicSuffixList = PublicSuffixList::new();

/// ListProvider is a generic struct that provides results based on a standard eTLD list generated by the included Golang program.
/// To override the list included with this crate, disable the `default_provider` crate feature
/// and create a `ListProvider` with your own implmentation of the [Table] trait, generated from your own
/// custom list.
pub struct ListProvider<T: Table>(PhantomData<T>);

/// The EffectiveTLDProvider trait allows other crates in `passkey-rs` to use
/// a custom domain TLD provider instead of using the `DEFAULT_PROVIDER` from
/// this crate.
pub trait EffectiveTLDProvider {
    /// Returns the effective top level domain plus one more label. For example,
    /// the eTLD+1 for "foo.bar.golang.org" is "golang.org".
    ///
    /// Note: The input string must be punycode (ASCII) and the result will be
    /// punycode (ASCII). The implementation of this function assumes each character
    /// is encoded in one byte; this assumption is inherent in the design of the
    /// generated table.
    ///
    /// It is recommended to use [idna::domain_to_ascii][1] to convert your inputs to
    /// ASCII punycode before passing to this method.
    ///
    /// [1]: https://docs.rs/idna/latest/idna/fn.domain_to_ascii.html
    fn effective_tld_plus_one<'a>(&self, domain: &'a str) -> Result<&'a str, Error>;
}

impl<T: Table> EffectiveTLDProvider for ListProvider<T> {
    fn effective_tld_plus_one<'a>(&self, domain: &'a str) -> Result<&'a str, Error> {
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return Err(Error::EmptyLabel);
        }

        let response = self.public_suffix(domain);
        if domain.len() <= response.len() {
            return Err(Error::CannotDeriveETldPlus1);
        }
        let i = domain.len() - response.len() - 1;

        if domain.as_bytes()[i] != b'.' {
            return Err(Error::InvalidPublicSuffix);
        }

        Ok(&domain[after_or_all(domain[..i].rfind('.'))])
    }
}

impl<T: Table> ListProvider<T> {
    /// Create a new ListProvider.
    pub const fn new() -> Self {
        ListProvider(PhantomData)
    }

    /// Returns the public suffix of the domain using a copy of the
    /// publicsuffix.org database compiled into the library (if using
    /// the `default_provider` crate feature) or your own impl of [Table].
    ///
    /// Note: The input string must be punycode (ASCII) and the result will be
    /// punycode (ASCII). The implementation of this function assumes each character
    /// is encoded in one byte; this assumption is inherent in the design of the
    /// generated table.
    ///
    /// It is recommended to use [idna::domain_to_ascii][1] to convert your inputs to
    /// ASCII punycode before passing to this method.
    ///
    /// [1]: https://docs.rs/idna/latest/idna/fn.domain_to_ascii.html
    pub fn public_suffix<'a>(&self, domain: &'a str) -> &'a str {
        let mut lo = 0_u32;
        let mut hi = T::NUM_TLD;

        let mut s = domain;
        let mut suffix = domain.len()..;
        let mut wildcard = false;

        'start: loop {
            let dot = s.rfind('.');
            if wildcard {
                suffix = after_or_all(dot);
            }
            if lo == hi {
                break;
            }
            let f = match self.find(&s[after_or_all(dot)], lo, hi) {
                Some(f) => f,
                None => {
                    break;
                }
            };

            let mut u = T::NODES[f] >> (T::NODES_BITS_TEXT_OFFSET + T::NODES_BITS_TEXT_LENGTH);
            u >>= T::NODES_BITS_ICANN;
            u = T::CHILDREN[(u & ((1 << T::NODES_BITS_CHILDREN) - 1)) as usize];
            lo = u & ((1 << T::CHILDREN_BITS_LO) - 1);
            u >>= T::CHILDREN_BITS_LO;
            hi = u & ((1 << T::CHILDREN_BITS_HI) - 1);
            u >>= T::CHILDREN_BITS_HI;
            match u & ((1 << T::CHILDREN_BITS_NODE_TYPE) - 1) {
                x if x == T::NODE_TYPE_NORMAL => {
                    suffix = after_or_all(dot);
                }
                x if x == T::NODE_TYPE_EXCEPTION => {
                    suffix = (1 + s.len())..;
                    break 'start;
                }
                _ => {
                    // Do nothing; keep going.
                }
            };
            u >>= T::CHILDREN_BITS_NODE_TYPE;
            wildcard = (u & ((1 << T::CHILDREN_BITS_WILDCARD) - 1)) != 0;
            match dot {
                Some(dot) => {
                    s = &s[..dot];
                }
                None => break,
            }
        }
        if suffix.start == domain.len() {
            // If no rules match, the prevailing rule is "*".
            suffix = after_or_all(domain.rfind('.'));
        };

        &domain[suffix]
    }

    // Returns the index of the node in the range [lo, hi) whose label equals
    // label, or `None` if there is no such node. The range is assumed to be in
    // strictly increasing node label order.
    fn find(&self, label: &str, mut lo: u32, mut hi: u32) -> Option<usize> {
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.node_label(mid) {
                s if s < label => {
                    lo = mid + 1;
                }
                s if s == label => {
                    return Some(mid as usize);
                }
                _ => {
                    hi = mid;
                }
            }
        }
        None
    }

    /// Finds the label for a node at a given index.
    fn node_label(&self, i: u32) -> &'static str {
        let mut x = T::NODES[i as usize];
        let length = (x & ((1 << T::NODES_BITS_TEXT_LENGTH) - 1)) as usize;
        x >>= T::NODES_BITS_TEXT_LENGTH;
        let offset = (x & ((1 << T::NODES_BITS_TEXT_OFFSET) - 1)) as usize;
        &T::TEXT[offset..][..length]
    }

    /// Returns true if `domain` is an effective top level domain.
    pub fn is_effective_tld(&self, domain: &str) -> bool {
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return false;
        }
        let response = self.public_suffix(domain);
        response == domain
    }
}

fn after_or_all(dot: Option<usize>) -> RangeFrom<usize> {
    match dot {
        Some(dot) => (dot + 1)..,
        None => 0..,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Error types returned from [`ListProvider::effective_tld_plus_one`]
pub enum Error {
    /// Returned when we cannot find the eTLD+1
    CannotDeriveETldPlus1,
    /// Returned when there is a missing part in the provided domain.
    EmptyLabel,
    /// Returned when there is something wrong with the provided domain.
    InvalidPublicSuffix,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use tld_list_test::*;

    #[test]
    fn node_label_test() {
        for (i, want) in NODE_LABELS.iter().enumerate() {
            assert_eq!(
                DEFAULT_PROVIDER.node_label(i.try_into().unwrap()),
                *want,
                "{i:?}: {want:?}"
            );
        }
    }

    #[test]
    fn find_test() {
        const TEST_CASES: &[&str] = &[
            "", "a", "a0", "aaaa", "ao", "ap", "ar", "aro", "arp", "arpa", "arpaa", "arpb", "az",
            "b", "b0", "ba", "z", "zu", "zv", "zw", "zx", "zy", "zz", "zzzz",
        ];

        for tc in TEST_CASES {
            let got = DEFAULT_PROVIDER.find(tc, 0, TLDList::NUM_TLD);
            let mut want = None;
            for i in 0..TLDList::NUM_TLD {
                if *tc == DEFAULT_PROVIDER.node_label(i) {
                    want = Some(i);
                    break;
                }
            }
            assert_eq!(got, want.map(|i| i as usize));
        }
    }
}
