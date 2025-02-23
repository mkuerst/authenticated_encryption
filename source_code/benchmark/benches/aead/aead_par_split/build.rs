// const SANITIZE: &str = "-fsanitize=address,bounds,bounds-strict,alignment,undefined";
// const DEBUG: &str = "-ldl";
// const DEBUG: &str = "-g";
// const SANITIZE: &str = "";
// const DEBUG: &str = "";

fn main() {
    // println!("cargo:rustc-link-lib=dylib=asan");
    // {xor_deadbeef, aes_baseline, cryptopp}

    // Rust versions don't need to be built here:
    #[cfg(not(any(
        feature = "xor_deadbeef",
        feature = "aes_256_gcm",
        feature = "cryptopp_gcm",
        feature = "aes128ctr_sha256",
        feature = "aes128ofb_sha256",
        feature = "aes256ctr_sha256",
        feature = "aes256ofb_sha256",
    )))]
    let build = 0;

    #[cfg(feature = "xor_deadbeef")]
    let build = 1;

    #[cfg(feature = "aes_256_gcm")]
    let build = 2;

    #[cfg(feature = "cryptopp_gcm")]
    let build = 3;

    #[cfg(feature = "aes128ctr_sha256")]
    let build = 4;
    #[cfg(feature = "aes128ofb_sha256")]
    let build = 5;
    #[cfg(feature = "aes256ctr_sha256")]
    let build = 6;
    #[cfg(feature = "aes256ofb_sha256")]
    let build = 7;

    match build {
        0 => {}
        1 => build_xor_deadbeef(),
        2 => build_aes("../baseline_aes_256_gcm/aes_256_gcm.c"),
        3 => build_cryptopp_gcm(),
        4 => build_aes("../aes-128-ctr_sha-256/aes-128-ctr_sha-256.c"),
        5 => build_aes("../aes-128-ofb_sha-256/aes-128-ofb_sha-256.c"),
        6 => build_aes("../aes-256-ctr_sha-256/aes-256-ctr_sha-256.c"),
        7 => build_aes("../aes-256-ofb_sha-256/aes-256-ofb_sha-256.c"),
        _ => unimplemented!(),
    }
}

fn get_cc_build() -> cc::Build {
    let mut build = cc::Build::new();
    build
        // .cc("gcc")
        // .flag(SANITIZE)
        // .flag(DEBUG)
        .opt_level(3)
        .warnings(true)
        .pic(true)
        .flag("-march=native");
    build
}

fn build_xor_deadbeef() {
    println!("cargo:warning=Linking with xor_deadbeef");
    let library_path = "../aead_xor_deadbeef/aead_xor_deadbeef.cpp";
    get_cc_build()
        .file(library_path)
        .compile("aead_xor_deadbeef");
}

fn build_aes(library_path: &str) {
    println!("cargo:warning=Linking with aes_256_gcm");
    get_cc_build()
        .flag("-lssl")
        .flag("-lcrypto")
        .file(library_path)
        .compile("aes_256_gcm");

    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:warning=linking ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:warning=linking crypto");
}

fn build_cryptopp_gcm() {
    println!("cargo:warning=Linking with cryptopp gcm");
    let library_path = "../cryptopp_gcm/cryptopp_gcm.cpp";
    get_cc_build()
        .cpp(true)
        .include("/usr/lib/x86_64-linux-gnu/")
        .flag("-std=c++11")
        .flag("-lcryptopp")
        .file(library_path)
        .compile("cryptopp_gcm");

    println!("cargo:rustc-link-lib=dylib=cryptopp");
    println!("cargo:warning=linking cryptopp");
}
