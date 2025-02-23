use core::slice;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn hash(in_buf: *const u8, out_buf: *mut u8, bytes: usize) -> usize {
    let mut hasher = blake3::Hasher::new();

    let input = slice::from_raw_parts(in_buf, bytes);

    // hasher.update(input);
    hasher.update_rayon(input);

    let output = slice::from_raw_parts_mut(out_buf, 32);
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(output);
    32
}
