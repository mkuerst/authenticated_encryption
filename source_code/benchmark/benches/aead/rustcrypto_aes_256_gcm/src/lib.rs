// TODO
#![allow(clippy::missing_safety_doc)]
use std::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};

use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Key, Nonce, Tag};

fn _get_key() -> &'static Key<Aes256Gcm> {
    let key: &[u8; 32] = &[42; 32];
    let key: &Key<Aes256Gcm> = key.into(); // TODO

    Key::<Aes256Gcm>::from_slice(key)
}

#[cfg(not(feature = "use_with_rust"))]
#[no_mangle]
pub unsafe extern "C" fn aead_encrypt(
    in_buf: *const u8,
    out_buf: *mut u8,
    mac: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    aead_encrypt_internal(in_buf, out_buf, mac, key, nonce, bytes)
}

#[cfg(feature = "use_with_rust")]
pub unsafe fn aead_encrypt(
    in_buf: *const u8,
    out_buf: *mut u8,
    mac: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    aead_encrypt_internal(in_buf, out_buf, mac, key, nonce, bytes)
}

unsafe fn aead_encrypt_internal(
    in_buf: *const u8,
    out_buf: *mut u8,
    mac: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    // println!("aead_encrypt: in_buf = {in_buf:?}, out_buf: {out_buf:?}, bytes: {bytes}");
    let input: &[u8] = &*slice_from_raw_parts(in_buf, bytes);
    // # SAFETY
    // out_buf must point to allocated memory large enough
    let output: &mut [u8] = &mut *slice_from_raw_parts_mut(out_buf, bytes);
    let mac: &mut [u8] = &mut *slice_from_raw_parts_mut(mac, 16);
    let key: &[u8] = &*slice_from_raw_parts(key, 32);
    let nonce: &[u8] = &*slice_from_raw_parts(nonce, 12);

    // encrypt(input, output)
    encrypt_in_place(input, output, mac, key, nonce)
}

fn encrypt_in_place(
    plaintext: &[u8],
    output: &mut [u8],
    mac: &mut [u8],
    key: &[u8],
    nonce: &[u8],
) -> usize {
    // let key = get_key();
    // let nonce = Nonce::default();
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    output.clone_from_slice(plaintext);
    if let Ok(tag) = cipher.encrypt_in_place_detached(nonce, b"", output) {
        mac[..tag.len()].clone_from_slice(tag.as_slice());
        output.len() + 16
    } else {
        0
    }
}

#[cfg(not(feature = "use_with_rust"))]
#[no_mangle]
pub unsafe extern "C" fn aead_decrypt(
    in_buf: *const u8,
    mac: *const u8,
    out_buf: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    aead_decrypt_internal(in_buf, mac, out_buf, key, nonce, bytes)
}

#[cfg(feature = "use_with_rust")]
pub unsafe fn aead_decrypt(
    in_buf: *const u8,
    mac: *const u8,
    out_buf: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    aead_decrypt_internal(in_buf, mac, out_buf, key, nonce, bytes)
}

unsafe fn aead_decrypt_internal(
    in_buf: *const u8,
    mac: *const u8,
    out_buf: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    let input: &[u8] = &*slice_from_raw_parts(in_buf, bytes);
    let mac: &[u8] = &*slice_from_raw_parts(mac, 16);
    let output: &mut [u8] = &mut *slice_from_raw_parts_mut(out_buf, bytes);
    let key: &[u8] = &*slice_from_raw_parts(key, 32);
    let nonce: &[u8] = &*slice_from_raw_parts(nonce, 12);

    match decrypt_in_place(input, mac, output, key, nonce) {
        Ok(()) => bytes,
        Err(()) => 0,
    }
}

fn decrypt_in_place(
    ciphertext: &[u8],
    mac: &[u8],
    output: &mut [u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<(), ()> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    output.clone_from_slice(&ciphertext[..output.len()]);
    cipher
        .decrypt_in_place_detached(nonce, b"", output, Tag::from_slice(mac))
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    // use aes_gcm::aead::{rand_core::RngCore, OsRng};
    use super::*;

    #[test]
    fn simple_test() {
        for i in 1..=64 {
            with_size(1024 * i);
        }
        for i in 16..=30 {
            let size = 1 << i;
            with_size(size);
        }
    }

    fn with_size(size: usize) {
        println!("encrypting sample plain text of size {size}");

        let plaintext = (0..size)
            .map(|x| (x % 256) as u8)
            .collect::<Vec<u8>>()
            .into_boxed_slice();

        let mut mac: Box<[u8]> = vec![0; 256].into_boxed_slice();
        let key: Box<[u8]> = (0..=255u8).collect();
        let nonce: Box<[u8]> = (0..=255u8).rev().collect();

        // let mut plaintext = vec![0; size].into_boxed_slice();
        // OsRng.fill_bytes(&mut plaintext);

        let mut output = vec![0; size];
        let mut decrypted_plaintext = vec![0; size];

        let in_buf = plaintext.as_ptr();
        let out_in_buf = output.as_mut_ptr();
        let mac_buf = mac.as_mut_ptr();
        let out_buf = decrypted_plaintext.as_mut_ptr();
        let key: *const u8 = key.as_ptr();
        let nonce = nonce.as_ptr();

        // let cypher_text_size = encrypt(&plaintext, &mut output);
        let cipher_text_size =
            unsafe { aead_encrypt(in_buf, out_in_buf, mac_buf, key, nonce, size) };
        println!("encryption done, cipher text size: {cipher_text_size}");
        assert!(cipher_text_size >= size);

        // let decrypted_plain_text_size =
        //     decrypt(&output[..cypher_text_size], &mut decrypted_plaintext);
        let decrypted_plain_text_size = unsafe {
            aead_decrypt(
                out_in_buf, mac_buf, out_buf, key, nonce, size, /* cypher_text_size */
            )
        };
        println!("decryption done, decoded plain text size: {decrypted_plain_text_size}");
        assert_eq!(decrypted_plain_text_size, size);

        let left = &plaintext[..];
        let right = &decrypted_plaintext[..decrypted_plain_text_size];
        assert_eq!(left.len(), right.len());
        assert_eq!(left, right);
    }
}
