// #![warn(clippy::pedantic)]

#[macro_use]
extern crate lazy_static;

use benchmark_rs::helper::config::{load, Config};
use benchmark_rs::{DecryptFunc, EncryptFunc, HashFunc, SetBlockSize, SetThreadCount};
use criterion::measurement::Measurement;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use std::path::Path;
use std::time::{Duration, Instant};

use benchmark_rs::helper::libraries::{
    self, get_block_size_set_function, get_decrypt_func, get_encrypt_func, get_hash_func,
    get_thread_count_set_function,
};
use benchmark_rs::helper::param::Param;

lazy_static! {
    static ref CONFIG: Config = load("config_bench.toml");
}

#[allow(dead_code)]
enum ThreadBenchStrategy {
    OneAndMax,
    All,
    PowersOfTwo,
}

/// ==> UNCOMMENT HERE TO CHANGE WHICH THREAD COUNTS GET BENCHMARKED <==
const THREAD_BENCH_STRATEGY: ThreadBenchStrategy = ThreadBenchStrategy::All;
// const THREAD_BENCH_STRATEGY: ThreadBenchStrategy = ThreadBenchStrategy::PowersOfTwo;
// const THREAD_BENCH_STRATEGY: ThreadBenchStrategy = ThreadBenchStrategy::OneAndMax;

/// This function determines which set of thread counts is benchmarked for parallel functions
fn thread_counts(max_threads: usize) -> Box<dyn Iterator<Item = usize>> {
    match THREAD_BENCH_STRATEGY {
        ThreadBenchStrategy::All => Box::new(1..=max_threads), // All values from 1 to max_threads
        ThreadBenchStrategy::OneAndMax => Box::new([1, max_threads].into_iter()), // Only 1 and max_threads
        ThreadBenchStrategy::PowersOfTwo => Box::new({
            let powers_of_two = (1..(usize::BITS)).filter_map(move |x| {
                // Only powers of 2 until max threads, and max_threads
                if x > usize::BITS {
                    return None;
                }
                let val = 1usize << x;
                (val <= max_threads).then_some(val)
            });
            let final_count = (!max_threads.is_power_of_two()).then_some(max_threads);
            powers_of_two.chain(final_count)
        }),
    }
}

/// Adjust this function to benchmark different block sizes:
fn get_block_sizes(input_size: usize) -> impl Iterator<Item = usize> {
    // [1024, 2048, 4096, ... , input_size / 4)
    (10..usize::BITS).filter_map(move |x| {
        let tmp = 1usize << x;
        (tmp / 2 / 4 < input_size).then_some(tmp)
    })
}

struct FuncNames<'a> {
    pub hash: &'a [&'a [u8]],
    pub encrypt: &'a [&'a [u8]],
    pub decrypt: &'a [&'a [u8]],
    pub set_threads: &'a [&'a [u8]],
    pub set_blocksize: &'a [&'a [u8]],
}

fn parse_algo_name(file_name: impl AsRef<Path>) -> String {
    let algo_name = file_name.as_ref().file_stem().unwrap().to_string_lossy();
    algo_name
        .strip_prefix("lib")
        .unwrap_or(&algo_name)
        .to_string()
}

fn do_runs(
    config: &Config,
    algo_name: &str,
    mut single_run: impl FnMut(&str),
    set_threads: &Option<SetThreadCount>,
    set_block_size: &Option<SetBlockSize>,
) {
    let mut did_run = false;
    if !config.do_only_blocksize_bench && config.do_thread_count_bench {
        if let Some(set_threads) = set_threads {
            if let Some(set_block_size) = set_block_size {
                assert!(set_block_size(0)); // Reset to default blocksize
            }
            for thr in thread_counts(config.max_threads) {
                did_run = true;
                set_threads(thr);
                let algo_name = format!("{algo_name}_par_{thr:03}");
                single_run(&algo_name);
            }
        }
    }
    if config.do_blocksize_bench {
        if let Some(set_block_size) = set_block_size {
            let algo_name = // TODO: try other thread counts
            if let Some(set_threads) = set_threads {
                let thr = (config.max_threads / 2).max(4);
                set_threads(thr);
                format!("{algo_name}_par_{thr:03}")
            } else {
                algo_name.to_string()
            };
            for block_size in get_block_sizes(config.input_size) {
                did_run = true;
                let algo_name = format!("{algo_name}_block_{block_size:012?}");
                if set_block_size(block_size) {
                    single_run(&algo_name);
                } else {
                    eprintln!("Could not set block size to {block_size} bytes for \"{algo_name}\"");
                }
            }
        }
    }
    if !did_run {
        single_run(algo_name);
    }
}

fn run_encrypt_benchmark<M: Measurement>(
    c: &mut Criterion<M>,
    config: &Config,
    param: &mut Param,
    func_names: &FuncNames<'_>,
    name: &str,
) -> Result<usize, ()> {
    let mut run_count = 0;
    let key_ptr = param.get_key().as_ptr();
    let nonce_ptr = param.get_nonce().as_ptr();

    let libraries: Vec<_> = libraries::lib_files(name, &config.name_patterns)
        .map_err(|_| ())?
        .collect();

    type FunctionTuple<'a> = (
        EncryptFunc<'a>,
        DecryptFunc<'a>,
        Option<SetThreadCount<'a>>,
        Option<SetBlockSize<'a>>,
    );
    let functions: Vec<(String, FunctionTuple)> = libraries
        .iter()
        .filter_map(|(file_path, lib)| {
            let encr = get_encrypt_func(lib, func_names.encrypt);
            let decr = get_decrypt_func(lib, func_names.decrypt);
            let set_thread_count = get_thread_count_set_function(lib, func_names.set_threads);
            let set_block_size = get_block_size_set_function(lib, func_names.set_blocksize);

            if config.do_only_blocksize_bench && set_block_size.is_none() {
                // eprintln!("Skipping \"{file_path:?}\", no way to set block size");
                return None; // Skip in blocksize-only mode, if implementation does not provide function to set block size
            }
            match (encr, decr) {
                (Some(encr), Some(decr)) => {
                    let algo_name = parse_algo_name(file_path);
                    Some((algo_name, (encr, decr, set_thread_count, set_block_size)))
                },
                _ => {
                    eprintln!("File {file_path:?} does not export the required functions for test \"{name}\", file skipped.");
                    None
                },
            }
        })
        .collect();

    let group_name = format!("{name}/encrypt");
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(param.input_size as u64));
    // TODO: check tradeoffs of Flat SampleMode
    group.sampling_mode(SamplingMode::Flat); // Enable flat sampling mode, used for longer-running benchmarks

    param.restore_input(); // TODO
    let mac_offset = {
        let diff = param.input_size % config.alignment;
        param.input_size + (config.alignment - diff) % config.alignment
    };
    for (algo_name, (encrypt_func, _, set_threads, set_block_size)) in &functions {
        // eprintln!("File name: {file_name:?}:\n\t{encrypt_func:?}\n\t_\n\t{set_threads:?}\n\t{set_block_size:?}");

        let single_run = |algo_name: &str| {
            run_count += 1;
            // param.restore_input(); // TODO
            let input = param.input_ptr();
            let output = param.output_ptr();
            let mac = unsafe { output.add(mac_offset) };
            let p = (input, output, mac, param.input_size);
            group.bench_with_input(BenchmarkId::new(algo_name, param.input_size), &p, |b, p| {
                b.iter(|| {
                    let write_bytes = encrypt_func(p.0, p.1, p.2, key_ptr, nonce_ptr, p.3);
                    assert!(
                        write_bytes != 0 && write_bytes >= param.input_size,
                        "Encryption function wrote an invalid number of bytes: {write_bytes}"
                    );
                })
            });
        };
        do_runs(config, algo_name, single_run, set_threads, set_block_size);
    }
    group.finish();

    let group_name = format!("{name}/decrypt");
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(param.input_size as u64));
    group.sampling_mode(SamplingMode::Flat); // Enable flat sampling mode, used for longer-running benchmarks

    for (algo_name, (encrypt_func, decrypt_func, set_threads, set_block_size)) in &functions {
        let single_run = |algo_name: &str| {
            run_count += 1;
            {
                param.restore_input(); // TODO this could probably be optimized, if we assume the encryption will never change the input buffer
                let input = param.input_ptr();
                let output = param.output_ptr();
                let mac = unsafe { output.add(mac_offset) };

                let write_bytes =
                    encrypt_func(input, output, mac, key_ptr, nonce_ptr, param.input_size);
                assert!(write_bytes != 0 && write_bytes >= param.input_size, "Encryption function for generating data wrote an invalid number of bytes: {write_bytes}");
                param.swap_buffers();
            }
            let input = param.input_ptr();
            let mac = unsafe { input.add(mac_offset) };
            let output = param.output_ptr();
            let p = (input, mac, output, param.input_size);
            group.bench_with_input(BenchmarkId::new(algo_name, param.input_size), &p, |b, p| {
                b.iter(|| {
                    let write_bytes = decrypt_func(p.0, p.1, p.2, key_ptr, nonce_ptr, p.3);
                    assert!(
                        write_bytes != 0 && write_bytes >= param.input_size,
                        "Decryption function wrote an invalid number of bytes: {write_bytes}"
                    );
                })
            });
        };
        do_runs(config, algo_name, single_run, set_threads, set_block_size);
    }
    group.finish();

    Ok(run_count)
}

fn run_hashing_benchmark<M: Measurement>(
    c: &mut Criterion<M>,
    config: &Config,
    param: &mut Param,
    func_names: &FuncNames<'_>,
    name: &str,
) -> Result<usize, ()> {
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Bytes(param.input_size as u64));
    group.sampling_mode(SamplingMode::Flat); // Enable flat sampling mode, used for longer-running benchmarks

    let mut run_count = 0;
    param.restore_input();
    for (file_name, lib) in libraries::lib_files(name, &config.name_patterns).map_err(|_| ())? {
        run_count += 1;
        let algo_name = parse_algo_name(&file_name);
        let file_name = file_name.to_string_lossy();

        let Some(hash_func): Option<HashFunc<'_>> = get_hash_func(&lib, func_names.hash) else {
            eprintln!("File {file_name} is a shared library, but does not export any of these functions: {:?}", func_names.hash);
            continue;
        };

        let set_block_size = get_block_size_set_function(&lib, &[b"set_block_size"]);
        if config.do_only_blocksize_bench && set_block_size.is_none() {
            continue; // Skip in blocksize-only mode, if implementation does not provide function to set block size
        }

        let input = param.input_ptr();
        let output = param.output_ptr();
        let input_size = param.input_size;
        let p = (input, output, input_size);
        let mut write_bytes = 0;
        group.bench_with_input(BenchmarkId::new(algo_name, input_size), &p, |b, p| {
            b.iter(|| {
                write_bytes = hash_func(p.0, p.1, p.2);
                assert!(write_bytes != 0, "Hashing function wrote zero bytes!");
            });
        });
        // TODO: could check if benchmark changed input data (currently assumed to not happen)

        eprint!("Output of hashing algorithm ({write_bytes} bytes): 0x");
        for v in &param.output()[..write_bytes] {
            eprint!("{v:x}");
        }
        eprintln!();
    }

    group.finish();
    Ok(run_count)
}

fn print_time(time: Duration, run_count: Option<usize>, name: &str) {
    let seconds = time.as_millis() as f64 / 1000.0;
    let hours = seconds / 3600.0;
    eprint!("\t{name}:       {seconds:.3?} seconds ~= {hours:.3?} hours. ");
    if let Some(count) = run_count {
        let mean_sec = seconds / count as f64;
        eprintln!("~= {mean_sec:.3?} sec/test, {count} tests in total");
    } else {
        eprintln!("(Something failed)");
    }
}

fn bench_all<M: Measurement>(c: &mut Criterion<M>) {
    let start = Instant::now();

    let config: &Config = &CONFIG;
    // Allocate buffers, generate/load data:
    let mut param = Param::new(config.input_size, config.alignment);

    eprintln!(
        "DATA SIZE: {} bytes ({:.3?} MiB, {:.3?} GiB)",
        config.input_size,
        config.input_size as f64 / 1024.0 / 1024.0,
        config.input_size as f64 / 1024.0 / 1024.0 / 1024.0
    );
    eprintln!("Physical cores: {}", num_cpus::get_physical());
    eprintln!("Logical cores:  {}", num_cpus::get());
    eprintln!("Benchmark: {config:#?}");

    let mut func_names = FuncNames {
        hash: &[b"hash", b"hash_parallel"],
        encrypt: &[b"encrypt", b"encrypt_parallel"],
        decrypt: &[b"decrypt", b"decrypt_parallel"],
        set_threads: &[b"set_thread_count"],
        set_blocksize: &[b"set_block_size"],
    };

    // Run the required benchmarks:
    let before_hash = Instant::now();
    let run_count_hash = if config.do_hashes {
        run_hashing_benchmark(c, config, &mut param, &func_names, "hash").ok()
    } else {
        None
    };
    let before_encrypt = Instant::now();
    let hash_time = before_encrypt.duration_since(before_hash);
    eprintln!(
        "Hashing benchmark took {} seconds",
        hash_time.as_millis() as f64 / 1000.0
    );
    let run_count_encryption = if config.do_encryption {
        let name = "encryption";
        run_encrypt_benchmark(c, config, &mut param, &func_names, name).ok()
    } else {
        None
    };
    let before_aead = Instant::now();
    let encryption_time = before_aead.duration_since(before_encrypt);
    eprintln!(
        "Encryption benchmark took {} seconds",
        encryption_time.as_millis() as f64 / 1000.0
    );
    let run_count_aead = if config.do_aead {
        let name = "aead";
        func_names.encrypt = &[b"aead_encrypt", b"aead_encrypt_parallel"];
        func_names.decrypt = &[b"aead_decrypt", b"aead_decrypt_parallel"];
        run_encrypt_benchmark(c, config, &mut param, &func_names, name).ok()
    } else {
        None
    };
    let end = Instant::now();
    let aead_time = end.duration_since(before_aead);
    println!(
        "AEAD benchmark took {} seconds",
        aead_time.as_millis() as f64 / 1000.0
    );

    // The rest is just printing:
    let time = end.duration_since(start);
    let seconds = time.as_millis() as f64 / 1000.0;
    let hours = seconds / 3600.0;
    eprintln!("Benchmark complete in {seconds:.3?} seconds ~= {hours:.3?} hours");

    if config.do_hashes {
        print_time(hash_time, run_count_hash, "Hash");
    }
    if config.do_encryption {
        print_time(encryption_time, run_count_encryption, "Encryption");
    }
    if config.do_aead {
        print_time(aead_time, run_count_aead, "AEAD");
    }
}

// For advanced configuration options:
// https://bheisler.github.io/criterion.rs/book/user_guide/advanced_configuration.html
criterion_group! {
    name = benches;
    config = Criterion::default()
        // .with_measurement(criterion_cycles_per_byte::CyclesPerByte) // Uncomment to switch to cycles & cycles per byte measurement (replace time measurement)
        .sample_size(CONFIG.sample_size)
        .measurement_time(CONFIG.measurement_time) // This sets the minimum benchmarking time
        .warm_up_time(CONFIG.warmup_time)
        .confidence_level(CONFIG.confidence_level);
        // .significance_level(0.01) // NOTE: Seems like we don't need this, it's for comparing multiple runs of 'cargo bench'
    targets = bench_all
}
criterion_main!(benches);
