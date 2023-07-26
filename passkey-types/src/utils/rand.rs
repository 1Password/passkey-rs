//! Random number generator utilities used for tests

use rand::RngCore;

fn random_fill(buffer: &mut [u8]) {
    let mut random = rand::thread_rng();
    random.fill_bytes(buffer);
}

/// Generate random data of specific length.
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    random_fill(&mut data);
    data
}
