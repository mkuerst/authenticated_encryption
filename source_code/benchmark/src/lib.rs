// #![warn(clippy::pedantic)]
pub mod helper;

pub type HashFunc<'a> = libloading::Symbol<'a, extern "C" fn(*const u8, *mut u8, usize) -> usize>;

pub type EncryptFunc<'a> = libloading::Symbol<
    'a,
    extern "C" fn(
        /* Plaintext */ *const u8,
        /* Ciphertext */ *mut u8,
        /* MAC */ *mut u8,
        /* Key */ *const u8,
        /* Nonce */ *const u8,
        usize,
    ) -> usize,
>;

pub type DecryptFunc<'a> = libloading::Symbol<
    'a,
    extern "C" fn(
        /* Ciphertext */ *const u8,
        /* MAC */ *const u8,
        /* Plaintext */ *mut u8,
        /* Key */ *const u8,
        /* Nonce */ *const u8,
        usize,
    ) -> usize,
>;

// Set the thread count to be used by the parallel implementation, 0 for automatic
pub type SetThreadCount<'a> = libloading::Symbol<'a, extern "C" fn(usize)>;

// Set the block size in bytes to be used by algorithms that use blocks
// returns true if block size has been accepted
pub type SetBlockSize<'a> = libloading::Symbol<'a, extern "C" fn(usize) -> bool>;
