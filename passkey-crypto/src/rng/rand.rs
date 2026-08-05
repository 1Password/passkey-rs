use ::rand::{Rng, rngs::ThreadRng};
use rand::RngExt;

use super::RngBackend;

impl RngBackend for ThreadRng {
    fn random_vec(len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let mut rng = ::rand::rng();
        rng.fill_bytes(&mut data);
        data
    }
    fn random_array<const N: usize>() -> [u8; N] {
        let mut rng = ::rand::rng();
        let mut bytes = [0u8; N];
        rng.fill(&mut bytes);
        bytes
    }

    fn from_range(range: std::ops::RangeInclusive<u8>) -> u8 {
        let mut rng = ::rand::rng();
        rng.random_range(range)
    }
}
