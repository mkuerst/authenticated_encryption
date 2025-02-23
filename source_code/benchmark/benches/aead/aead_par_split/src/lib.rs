// #![warn(clippy::pedantic)]

use std::sync::atomic::AtomicUsize;

use rayon::prelude::*;

// http://blog.asleson.org/2021/02/23/how-to-writing-a-c-shared-library-in-rust/

const fn max(a: usize, b: usize) -> usize {
    if a >= b {
        a
    } else {
        b
    }
}

// // https://users.rust-lang.org/t/pass-numeric-compile-time-arguments/59093
// const fn parse_usize(s: &str) -> usize {
//     let mut out: usize = 0;
//     let mut i: usize = 0;
//     let bytes = s.as_bytes();
//     assert!(!bytes.is_empty(), "String is empty");
//     while i < s.len() {
//         out *= 10;
//         assert!(!(bytes[i] < b'0' || bytes[i] > b'9'), "String must contain a number, but did not");
//         out += (bytes[i] - b'0') as usize;
//         i += 1;
//     }
//     out
// }

// const BYTES_PER_BLOCK: usize = {
//     if let Some(val) = option_env!("PAR_SPLIT_BLOCK_SIZE") {
//         parse_usize(val)
//     } else {
//         256 * 1024
//     }
// };

const DEFAULT_BLOCKSIZE: usize = 16 * 1024;
static BYTES_PER_BLOCK: AtomicUsize = AtomicUsize::new(DEFAULT_BLOCKSIZE);

#[no_mangle]
pub extern "C" fn set_block_size(new_block_size: usize) -> bool {
    if new_block_size == 0 {
        BYTES_PER_BLOCK.store(DEFAULT_BLOCKSIZE, std::sync::atomic::Ordering::Relaxed);
        true
    } else if new_block_size % 64 != 0 {
        false
    } else {
        BYTES_PER_BLOCK.store(new_block_size, std::sync::atomic::Ordering::Relaxed);
        true
    }
}

// const BYTES_PER_BLOCK: usize = 256 * 1024; // 1024 * 1024; // 1024; // 32 * 1024;
const EXTRA_BYTES_PER_BLOCK: usize = max(64, 512 / 8); // 64 bytes for Cache alignment
                                                       // const BYTES_PER_AEAD_BLOCK: usize = BYTES_PER_BLOCK.load(std::sync::atomic::Ordering::Relaxed) + EXTRA_BYTES_PER_BLOCK;

#[cfg(feature = "rustcrypto_aes_256_gcm")]
use rustcrypto_aes_256_gcm::{aead_decrypt, aead_encrypt};

#[cfg(feature = "rustcrypto_aes_256_blake3")]
use rustcrypto_aes_256_blake3::{aead_decrypt, aead_encrypt};

#[cfg(not(any(feature = "rustcrypto_aes_256_gcm", feature= "rustcrypto_aes_256_blake3")))]
extern "C" {
    fn aead_encrypt(
        in_buf: *const u8,
        out_buf: *mut u8,
        mac: *mut u8,
        key: *const u8,
        nonce: *const u8,
        bytes: usize,
    ) -> usize;
    fn aead_decrypt(
        in_buf: *const u8,
        mac: *const u8,
        out_buf: *mut u8,
        key: *const u8,
        nonce: *const u8,
        bytes: usize,
    ) -> usize;
}

#[derive(Clone, Copy, Debug)]
struct Param<M> {
    in_buf: *const u8,
    out_buf: *mut u8,
    mac: M,
    key: *const u8,
    nonce: *const u8,
}

unsafe impl<M> std::marker::Sync for Param<M> {}
unsafe impl<M> std::marker::Send for Param<M> {}

static mut THREAD_POOL: Option<rayon::ThreadPool> = None;

#[no_mangle]
/// # Safety
/// This function is not thread_safe, it may only be called when no other functions exported by this crate are getting executed
pub unsafe extern "C" fn set_thread_count(new_count: usize) {
    THREAD_POOL = Some(
        rayon::ThreadPoolBuilder::new()
            .num_threads(new_count)
            .build()
            .unwrap(),
    );
}

/// # Safety
/// `in_buf` and `out_buf` are not allowed to alias or overlap
/// Both buffers must point to allocated memory of size at least `bytes` for `in_buf`,
/// and `bytes + (bytes / BYTES_PER_BLOCK * (BYTES_PER_BLOCK + EXTRA_BYTES_PER_BLOCK))`
#[no_mangle]
pub unsafe extern "C" fn aead_encrypt_parallel(
    in_buf: *const u8,
    out_buf: *mut u8,
    mac: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    let thread_pool = if let Some(thread_pool) = &THREAD_POOL {
        thread_pool
    } else {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            // .num_threads(1)
            .build()
            .unwrap();
        THREAD_POOL = Some(thread_pool);
        THREAD_POOL.as_ref().unwrap()
    };
    let bytes_per_block = BYTES_PER_BLOCK.load(std::sync::atomic::Ordering::Relaxed);
    let block_count = bytes / bytes_per_block;
    let param = &Param {
        in_buf,
        out_buf,
        mac,
        key,
        nonce,
    };

    let aead_single = |index: usize| {
        let offset_plain = bytes_per_block * index;
        let offset_cipher = bytes_per_block * index;
        let curr_block_bytes = if index == block_count {
            let rem = bytes - block_count * bytes_per_block;
            if rem == 0 {
                return (0, true);
            }
            rem
        } else {
            bytes_per_block
        };
        let offset_mac = index * EXTRA_BYTES_PER_BLOCK;
        let in_buf = param.in_buf.add(offset_plain);
        let out_buf = param.out_buf.add(offset_cipher);
        let mac_buf = param.mac.add(offset_mac);

        // println!("ENCRYPTION: {curr_block_bytes} bytes, Offsets[{index}]: {offset_plain}, {offset_cipher}, {offset_mac}, addresses: input: {:?}, output: {:?}, mac: {:?}", in_buf, out_buf, mac_buf);

        let bytes_written = aead_encrypt(
            in_buf,
            out_buf,
            mac_buf,
            param.key,
            param.nonce,
            curr_block_bytes,
        );
        // println!("{index}: bytes_written: {bytes_written}, value: {:x?}, {:x?}", *(mac_buf as *mut u64), *((mac_buf as *mut u64).wrapping_add(1)));
        if bytes_written == 0 {
            eprintln!("WARNING (ENCRYPTION): block {index} wrote 0 bytes!");
            (0, false)
        } else {
            (bytes_written, true)
        }
    };
    let (bytes_written, all_ok) = thread_pool.install(|| {
        (0..=block_count).into_par_iter().map(aead_single).reduce(
            || (0usize, true),
            |(l_bytes, l_ok), (r_bytes, r_ok)| {
                if l_ok && r_ok {
                    (l_bytes + r_bytes, true)
                } else {
                    (0, false)
                }
            },
        )
    });
    if all_ok {
        bytes_written
    } else {
        0
    }
}

/// # Safety
/// Safety is left as an exercise to the user of this function (TODO)
/// (Same requirements as `aead_encrypt_parallel`)
#[no_mangle]
pub unsafe extern "C" fn aead_decrypt_parallel(
    in_buf: *const u8,
    mac: *const u8,
    out_buf: *mut u8,
    key: *const u8,
    nonce: *const u8,
    bytes: usize,
) -> usize {
    let thread_pool = THREAD_POOL.as_ref().unwrap();
    let bytes_per_block = BYTES_PER_BLOCK.load(std::sync::atomic::Ordering::Relaxed);
    let block_count = bytes / bytes_per_block;
    let param = &Param {
        in_buf,
        out_buf,
        mac,
        key,
        nonce,
    };

    let aead_single = |index: usize| {
        let offset_cipher = bytes_per_block * index;
        let curr_block_bytes = if index == block_count {
            let rem = bytes - block_count * bytes_per_block;
            if rem == 0 {
                return (0, true);
            }
            rem
        } else {
            bytes_per_block
        };
        let offset_mac = index * EXTRA_BYTES_PER_BLOCK;
        let offset_plain = bytes_per_block * index;
        let in_buf = param.in_buf.add(offset_cipher);
        let mac_buf = param.mac.add(offset_mac);
        let out_buf = param.out_buf.add(offset_plain);

        // println!("ENCRYPTION: {curr_block_bytes} bytes, Offsets[{index}]: {offset_plain}, {offset_cipher}, {offset_mac}, addresses: ciphertext: {:?}, mac: {:?}, output buffer: {:?}", in_buf, mac_buf, out_buf);

        let bytes_written = aead_decrypt(
            in_buf,
            mac_buf,
            out_buf,
            param.key,
            param.nonce,
            curr_block_bytes,
        );
        // println!("{index}: bytes_written: {bytes_written}, value: {:x?}, {:x?}", *(mac_buf as *mut u64), *((mac_buf as *mut u64).wrapping_add(1)));
        if bytes_written == 0 {
            eprintln!("WARNING (DECRYPTION): block {index} wrote 0 bytes!");
            (0, false)
        } else {
            (bytes_written, true)
        }
    };
    let (bytes_written, all_ok) = thread_pool.install(|| {
        (0..=block_count).into_par_iter().map(aead_single).reduce(
            || (0usize, true),
            |(l_bytes, l_ok), (r_bytes, r_ok)| {
                if l_ok && r_ok {
                    (l_bytes + r_bytes, true)
                } else {
                    (0, false)
                }
            },
        )
    });
    if all_ok {
        bytes_written
    } else {
        0
    }
}
