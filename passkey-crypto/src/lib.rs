//!

pub mod rng;

pub trait CryptoBackend {
    type Rng: rng::RngBackend;
}
