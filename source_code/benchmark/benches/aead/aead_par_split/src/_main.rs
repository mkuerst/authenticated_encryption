use aead_par_split::aead_encrypt_parallel;

fn main() {
    let size = 1024;
    let align = 64;
    let input = vec![0; 2 * size + align].into_boxed_slice();
    let mut output = vec![0; 2 * size + align].into_boxed_slice();
    let diff0 = align - input.as_ptr() as usize % align;
    let diff1 = align - input.as_ptr() as usize % align;

    let input = &input[diff0..];
    let output = &mut output[diff1..];
    let in_buf = input.as_ptr();
    let out_buf = output.as_mut_ptr();

    let write_bytes = unsafe { aead_encrypt_parallel(in_buf, out_buf, size) };

    println!("Gave {size} bytes, AEAD wrote {write_bytes} bytes:");
    println!("Input:  {:x?}", &input[..size]);
    println!("Output: {:x?}", &output[..write_bytes]);
}
