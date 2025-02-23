// #![no_std] // TODO: try no_std with other implementations
// #![warn(clippy::pedantic)]
use core::slice;

use ghash::{
    universal_hash::{crypto_common::KeySizeUser, KeyInit, UniversalHash},
    GHash,
};

#[no_mangle]
#[allow(clippy::missing_safety_doc)] // TODO
pub unsafe extern "C" fn hash(in_buf: *const u8, out_buf: *mut u8, bytes: usize) -> usize {
    // let ghash_key = ghash::Key::default();
    // NOTE: Random guess at a starting key (AES_GCM uses AES to create this, by encrypting the default key (all zeroes))
    #[allow(clippy::cast_possible_truncation)]
    let ghash_key = (0..GHash::key_size()).map(|val| (val % (u8::MAX as usize)) as u8).collect();
        // ghash::Key::from_iter((0..GHash::key_size()).map(|val| (val % (u8::MAX as usize)) as u8));
    let mut ghash = GHash::new(&ghash_key);

    // Safety: in_buf ptr must point to allocated memory that is at least `bytes` bytes large
    let data = slice::from_raw_parts(in_buf, bytes);
    ghash.update_padded(data);

    let hash = ghash.finalize();
    // println!(
    //     "Hashed {} bytes of data with ghash, got {} bytes of hash: {:?}, ghash_key: {ghash_key:?}",
    //     data.len(),
    //     hash.len(),
    //     hash
    // );
    // println!("512 bytes of data: {:?}", &data[..512]);

    // Safety: out_buf ptr must point to allocated memory that is at least `output.len()` bytes large
    let out_buf = slice::from_raw_parts_mut(out_buf, hash.len());
    out_buf.clone_from_slice(&hash);
    hash.len()
}
