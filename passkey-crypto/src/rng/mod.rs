//! Implements the various number generator backends.
//!
//! Each backend is mutually exclusive, therefore only one backend may be used at a time.
//! Currently the implemented backends are:
//! * `rand`: Using `::rand::thread_rng`

#[cfg(feature = "rand")]
mod rand;

use std::ops::RangeInclusive;

#[cfg(feature = "rand")]
use rand::*;

/// The methods that all Random Number Generator backends must implement for use accross the passkey
/// crates.
pub trait RngBackend: Sized {
    /// TEMP: until key creation is self contained in CryptoBackend
    fn new() -> Self;
    /// Generate random data of specific length.
    fn random_vec(len: usize) -> Vec<u8>;
    /// Generate a fixed size array of random bytes
    fn random_array<const N: usize>() -> [u8; N];
    /// Randomly select a number from a given range
    fn from_range(range: RangeInclusive<u8>) -> u8;
}

/// The enabled Random Number Generator backend
pub type Rng = _Rng;
