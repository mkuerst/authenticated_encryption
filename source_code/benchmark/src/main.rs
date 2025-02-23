// #![warn(clippy::pedantic)]
use std::{
    env,
    fs::File,
    io::{stderr, StderrLock, Write},
    path::{Path, PathBuf},
};

use benchmark_rs::{
    helper::{
        libraries::{self, get_decrypt_func, get_encrypt_func, get_hash_func},
        param::Param,
    },
    DecryptFunc, EncryptFunc, HashFunc,
};
use std::time::Instant;

const DEFAULT_ALIGNMENT: usize = 64; // Align to one cache line (64 bytes == 512 bits)
const DEFAULT_INPUT_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB
const LINE_OF_LINES: &str =
    "-----------------------------------------------------------------------------";

const HASH_NAME: &str = "hash";
const HASH_FUNC_NAMES: &[&[u8]] = &[b"hash", b"hash_parallel"];
type ByteArray<'a> = &'a [&'a [u8]];
const ENCR_NAMES: &[(&str, (ByteArray, ByteArray))] = {
    let encryption_name = "encryption";
    let encryption_enc_func: &[&[u8]] = &[b"encrypt", b"encrypt_parallel"];
    let encryption_dec_func: &[&[u8]] = &[b"decrypt", b"decrypt_parallel"];

    let aead_name = "aead";
    let aead_enc_func: &[&[u8]] = &[b"aead_encrypt", b"aead_encrypt_parallel"];
    let aead_dec_func: &[&[u8]] = &[b"aead_decrypt", b"aead_decrypt_parallel"];

    &[
        (encryption_name, (encryption_enc_func, encryption_dec_func)),
        (aead_name, (aead_enc_func, aead_dec_func)),
    ]
};

fn main() {
    let mut args = env::args();
    args.next(); // Skip executable name

    let mut input_size = DEFAULT_INPUT_SIZE;
    let mut extra_target = None;
    if let Some(arg) = args.next() {
        if let Ok(size) = arg.parse() {
            input_size = size;
        } else {
            extra_target = Some(arg);
        }
    }
    if input_size < DEFAULT_ALIGNMENT {
        println!(
            "WARNING: data size {input_size} bytes is too small, increasing to {DEFAULT_ALIGNMENT} bytes!"
        );
        input_size = DEFAULT_ALIGNMENT;
    }
    let mut targets: Vec<String> = args.collect();
    targets.extend(extra_target);
    println!("Executing tests for functions matching any of {targets:?}");

    let mut param = Param::new(input_size, DEFAULT_ALIGNMENT);

    param.restore_input();
    if let Ok(libs) = libraries::lib_files(HASH_NAME, &targets).map_err(|_| ()) {
        bench_hashes(libs, &mut param);
    }

    println!("{}", LINE_OF_LINES);
    println!("{}", LINE_OF_LINES);

    for (name, (encrypt_func_names, decrypt_func_names)) in ENCR_NAMES {
        println!("Running: \"{name}\"");
        let Ok(libs) = libraries::lib_files(name, &targets).map_err(|_| ()) else {
            println!("Skip...");
            continue;
        };
        bench_encrypt(libs, &mut param, encrypt_func_names, decrypt_func_names);
    }
}

fn bench_hashes(libs: impl Iterator<Item = (PathBuf, libloading::Library)>, param: &mut Param) {
    for (file_name, lib) in libs {
        let file_name = file_name.to_string_lossy();
        println!("Running hashing function: {file_name}");

        let hash_func: HashFunc<'_> = if let Some(f) = get_hash_func(&lib, HASH_FUNC_NAMES) {
            f
        } else {
            eprintln!("File {file_name} is a shared library, but does not export any of these functions: {HASH_FUNC_NAMES:?}");
            continue;
        };

        let start = Instant::now();
        let write_count = hash_func(param.input_ptr(), param.output_ptr(), param.input_size);
        let time = Instant::now().duration_since(start);
        assert!(write_count != 0);

        let mut stderr = stderr().lock();
        #[allow(clippy::cast_precision_loss)]
        let time_ms = time.as_nanos() as f64 / 1_000_000.0;
        write!(
            stderr,
            "Hashing output ({time_ms} ms) ({write_count} bytes): 0x"
        )
        .unwrap();
        // TODO: could check if benchmark changed input data (currently assumed to not happen)
        for v in &param.output()[..write_count] {
            write!(stderr, "{v:x}").unwrap();
        }
        writeln!(stderr).unwrap();
        writeln!(stderr, "{LINE_OF_LINES}").unwrap();
        writeln!(stderr).unwrap();
    }
    println!("HASHES DONE!");
}

fn bench_encrypt(
    libs: impl Iterator<Item = (PathBuf, libloading::Library)>,
    param: &mut Param,
    encrypt_func_names: ByteArray,
    decrypt_func_names: ByteArray,
) {
    let input_size = param.input_size;
    let key_ptr = param.get_key().as_ptr();
    let nonce_ptr = param.get_nonce().as_ptr();
    let libraries: Vec<_> = libs.collect();
    let functions: Vec<(EncryptFunc<'_>, DecryptFunc<'_>)> = libraries
        .iter()
        .filter_map(|(file_path, lib)| {
            let encr = get_encrypt_func(lib, encrypt_func_names);
            let decr = get_decrypt_func(lib, decrypt_func_names);
            if let (Some(encr), Some(decr)) = (encr, decr) {
                Some((encr, decr))
            } else {
                eprintln!("File {file_path:?} does not export the required functions for test, file skipped.");
                None
            }
        })
        .collect();
    for ((file_path, _), (encrypt_func, decrypt_func)) in libraries.iter().zip(functions.iter()) {
        let file_name = file_path.to_string_lossy();
        println!("Testing encryption and decryption with \"{file_name}\"");
        let mac_offset = {
            let diff = param.input_size % DEFAULT_ALIGNMENT;
            param.input_size + (DEFAULT_ALIGNMENT - diff) % DEFAULT_ALIGNMENT
        };
        {
            param.restore_input();
            let output_ptr = param.output_ptr();
            let mac = unsafe { output_ptr.add(mac_offset) };
            let start = Instant::now();
            let write_count_encr = encrypt_func(
                param.input_ptr(),
                output_ptr,
                mac,
                key_ptr,
                nonce_ptr,
                param.input_size,
            );
            let time = Instant::now().duration_since(start);
            #[allow(clippy::cast_precision_loss)]
            let time_ms = time.as_nanos() as f64 / 1_000_000.0;
            #[allow(clippy::cast_possible_wrap)]
            let diff = write_count_encr as isize - input_size as isize;
            println!("  Encryption function wrote {write_count_encr} bytes in {time_ms} ms (Plaintext size: {input_size} bytes, diff: {diff})");
            assert!(write_count_encr != 0);
        }

        param.swap_buffers();
        {
            let input_ptr = param.input_ptr();
            let mac = unsafe { input_ptr.add(mac_offset) };
            let start = Instant::now();
            let write_count_decr = decrypt_func(
                input_ptr,
                mac,
                param.output_ptr(),
                key_ptr,
                nonce_ptr,
                param.input_size,
            );
            let time = Instant::now().duration_since(start);

            let mut stderr = stderr().lock();
            #[allow(clippy::cast_precision_loss)]
            let time_ms = time.as_nanos() as f64 / 1_000_000.0;
            writeln!(stderr, "  Decryption function wrote {write_count_decr} bytes in {time_ms} ms (Plaintext size: {input_size} bytes)").unwrap();
            assert_eq!(write_count_decr, input_size);

            if param.check_correct_output() {
                writeln!(stderr, "Cyphertext was decoded correctly").unwrap();
            } else {
                print_buf_to_file(&mut stderr, file_path, param, write_count_decr);
            }
            writeln!(stderr, "{LINE_OF_LINES}").unwrap();
            writeln!(stderr).unwrap();
        }
    }
}

fn print_buf_to_file(
    stderr: &mut StderrLock,
    file_path: &Path,
    param: &Param,
    write_count_decr: usize,
) {
    writeln!(
        stderr,
        "ERROR: Decrypted data does not match plaintext data!"
    )
    .unwrap();
    let path = format!(
        "./target/{}_input_plaintext.txt",
        file_path.file_name().unwrap().to_str().unwrap()
    );
    writeln!(stderr, "  writing plaintext to file \"{path}\"").unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(param.get_backup()).unwrap();

    let path = format!(
        "./target/{}_cyphertext.txt",
        file_path.file_name().unwrap().to_str().unwrap()
    );
    writeln!(stderr, "  writing cyphertext to file \"{path}\"").unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(&param.input()[..param.input_size]).unwrap();

    let path = format!(
        "./target/{}_decoded_plaintext.txt",
        file_path.file_name().unwrap().to_str().unwrap()
    );
    writeln!(
        stderr,
        "  writing (incorrectly decoded) plaintext to file \"{path}\""
    )
    .unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(&param.output()[..write_count_decr]).unwrap();
}
