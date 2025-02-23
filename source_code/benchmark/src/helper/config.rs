use std::{fs, time::Duration};

use toml::{Table, Value};

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Config {
    pub input_size: usize,
    pub max_threads: usize,

    pub sample_size: usize,
    pub measurement_time: Duration,
    pub warmup_time: Duration,

    pub confidence_level: f64,
    pub alignment: usize,

    pub do_hashes: bool,
    pub do_encryption: bool,
    pub do_aead: bool,
    pub do_thread_count_bench: bool,
    pub do_blocksize_bench: bool,
    pub do_only_blocksize_bench: bool,

    pub name_patterns: Vec<String>,
}

trait ParseValue {
    fn to_usize_or(&self, default: usize) -> usize;
    fn to_bool_or(&self, default: bool) -> bool;
    fn to_u64_or(&self, default: u64) -> u64;
    fn to_f64_or(&self, default: f64) -> f64;
}

impl ParseValue for Option<&Value> {
    fn to_usize_or(&self, default: usize) -> usize {
        self.map(Value::as_integer)
            .flatten()
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or_else(|| {
                eprintln!("Cannot convert value: \"{self:?}\" to usize, using default value \"{default}\"");
                default
            })
    }

    fn to_bool_or(&self, default: bool) -> bool {
        self.map(Value::as_bool).flatten().unwrap_or_else(|| {
            eprintln!(
                "Cannot convert value: \"{self:?}\" to bool, using default value \"{default}\""
            );
            default
        })
    }

    fn to_f64_or(&self, default: f64) -> f64 {
        self.map(Value::as_float).flatten().unwrap_or_else(|| {
            eprintln!(
                "Cannot convert value: \"{self:?}\" to usize, using default value \"{default}\""
            );
            default
        })
    }

    fn to_u64_or(&self, default: u64) -> u64 {
        self.map(Value::as_integer)
            .flatten()
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or_else(|| {
                eprintln!("Cannot convert value: \"{self:?}\" to usize, using default value \"{default}\"");
                default
            })
    }
}

fn load_from_file(file_path: &str) -> Table {
    let Ok(config_toml) = fs::read_to_string(file_path) else {
        eprintln!("Config file does not exist, expected file: \"{file_path}\"");
        return Table::new();
    };
    let Ok(config) = config_toml.parse::<Table>() else {
        eprintln!("Config is not a valid toml file");
        return Table::new();
    };
    config
}

pub fn load(file_path: &str) -> Config {
    const DEFAULT_ALIGNMENT: usize = 64; // Align to one cache line (64 bytes == 512 bits)
    const DEFAULT_INPUT_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB
    const DEFAULT_SAMPLE_SIZE: usize = 100;
    const DEFAULT_MEASUREMENT_TIME_SEC: u64 = 1;
    const DEFAULT_WARMUP_TIME_SEC: u64 = 3;
    const DEFAULT_CONFIDENCE_LEVEL: f64 = 0.99;

    let config = load_from_file(file_path);
    let input_size = config.get("INPUT_SIZE").to_usize_or(DEFAULT_INPUT_SIZE);
    let alignment = config.get("ALIGNMENT").to_usize_or(DEFAULT_ALIGNMENT);

    let sample_size = config.get("SAMPLE_SIZE").to_usize_or(DEFAULT_SAMPLE_SIZE);
    let measurement_time = Duration::from_secs(
        config
            .get("MEASUREMENT_TIME_SEC")
            .to_u64_or(DEFAULT_MEASUREMENT_TIME_SEC),
    );
    let warmup_time = Duration::from_secs(
        config
            .get("WARMUP_TIME_SEC")
            .to_u64_or(DEFAULT_WARMUP_TIME_SEC),
    );
    let confidence_level = config
        .get("CONFIDENCE_LEVEL")
        .to_f64_or(DEFAULT_CONFIDENCE_LEVEL);

    let do_hashes = config.get("BENCH_HASH").to_bool_or(true);
    let do_encryption = config.get("BENCH_ENCRYPTION").to_bool_or(true);
    let do_aead = config.get("BENCH_AEAD").to_bool_or(true);

    let do_thread_count_bench = config.get("DO_THREAD_COUNT_BENCH").to_bool_or(true);
    let do_blocksize_bench = config.get("DO_BLOCK_SIZE_BENCH").to_bool_or(false);
    let do_only_blocksize_bench = config.get("DO_ONLY_BLOCKSIZE_BENCH").to_bool_or(false);

    // Include only tests matching one of these strings (leave empty for no filtering)
    let name_patterns = if let Some(Value::Array(patterns)) = config.get("NAME_PATTERNS") {
        patterns
            .iter()
            .filter_map(|pattern| pattern.as_str())
            .map(std::borrow::ToOwned::to_owned)
            .collect()
    } else {
        Vec::new()
    };

    Config {
        alignment,
        input_size,
        max_threads: num_cpus::get(),

        sample_size,
        measurement_time,
        warmup_time,
        confidence_level,

        do_hashes,
        do_encryption,
        do_aead,

        do_thread_count_bench,
        do_blocksize_bench,
        do_only_blocksize_bench,

        name_patterns,
    }
}
