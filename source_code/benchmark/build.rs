use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use rayon::prelude::*;

const DIRS: [&str; 3] = ["hash", "encryption", "aead"];
const BUILD_DIR: &str = "target/build";
const LIB_DIR: &str = "target/dynlibs";
const SRC_DIR: &str = "benches";

fn main() {
    // println!("cargo:rustc-link-lib=dylib=asan");

    // create a dirctory for dynamic libraries
    let failed_count: usize = DIRS
        .par_iter()
        .map(|dir| {
            fs::create_dir_all(Path::new(BUILD_DIR).join(dir)).expect("failed to create build dir");
            fs::create_dir_all(Path::new(LIB_DIR).join(dir)).expect("failed to create lib dir");

            let algos: Box<[_]> = fs::read_dir(Path::new(SRC_DIR).join(dir))
                .unwrap_or_else(|_| panic!("failed to read dir {}", dir))
                .collect();

            let lib_dir = Path::new(LIB_DIR).join(dir);

            algos
                .into_par_iter()
                .map(|algo| {
                    {
                        let Ok(algo) = algo else {
                            println!("cargo:warning=Could not compile {algo:?}");
                            return 1;
                        };
                        if !algo.metadata().expect("unable to read metadata").is_dir() {
                            return 0;
                        }
                        let algo = algo.file_name();
                        let algo_name = algo.to_string_lossy();
                        if algo_name.contains("_Disabled") {
                            return 0;
                        }

                        // create a build dir for algorithm
                        let build_dir = Path::new(BUILD_DIR).join(dir).join(algo_name.as_ref());
                        fs::create_dir_all(&build_dir).unwrap_or_else(|_| {
                            panic!("failed to create build dir {}", build_dir.to_string_lossy())
                        });

                        let src_dir = Path::new(SRC_DIR).join(dir).join(algo_name.as_ref());

                        let prefix = Path::new("../../..");
                        // use make to compile the dynamic library
                        let start = Instant::now();
                        let output = Command::new("make")
                            .arg("-C")
                            .arg(src_dir)
                            .arg(format!(
                                "BUILD_DIR={}",
                                prefix.join(&build_dir).to_string_lossy()
                            ))
                            .arg(format!(
                                "LIB_DIR={}",
                                prefix.join(&lib_dir).to_string_lossy()
                            ))
                            .output()
                            .expect("failed to execute \"make\"");
                        let end = Instant::now();
                        let time = end.duration_since(start);

                        let extra = if output.status.success() {
                            ""
                        } else {
                            " <-- FAILURE"
                        };
                        println!(
                            "cargo:warning=[{:>8} ms] Make for {algo_name:26} exited with {}{extra}",
                            time.as_millis(),
                            output.status
                        );
                        if output.status.success() {
                            0usize
                        } else {
                            1usize
                        }
                    }
                })
                .sum::<usize>()
        })
        .sum();

    println!("cargo:warning===========================================");
    println!("cargo:warning={failed_count} programs failed to compile.");
    println!("cargo:warning===========================================");

    println!("cargo:rerun-if-changed=benches/aead");
    println!("cargo:rerun-if-changed=benches/encryption");
    println!("cargo:rerun-if-changed=benches/hash");
    println!("cargo:rerun-if-changed=build.rs");

    // // Build the data generator function:
    // println!("cargo:rerun-if-changed=../data_generator/generate_file.c");
    // cc::Build::new()
    //     // .cc("gcc")
    //     .file("../data_generator/generate_file.c")
    //     .flag("-O3")
    //     .flag("-march=native")
    //     .compile("write_input_to_file");
}
