use ::rand::{Rng, RngCore, rngs::ThreadRng};

use super::RngBackend;

pub(super) type _Rng = ThreadRng;

impl RngBackend for ThreadRng {
    fn new() -> Self {
        ::rand::thread_rng()
    }
    fn random_vec(len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let mut rng = ::rand::thread_rng();
        rng.fill_bytes(&mut data);
        data
    }
    fn random_array<const N: usize>() -> [u8; N] {
        let mut rng = ::rand::thread_rng();
        // The rand crate has updated this wording in version 0.9 and above.
        // Unfortunately, the RustCrypto ecosystem hasn't updated yet so here we are.
        rng.r#gen()
    }

    fn from_range(range: std::ops::RangeInclusive<u8>) -> u8 {
        let mut rng = ::rand::thread_rng();
        rng.gen_range(range)
    }
}
