include ../../base.mk

export RUSTFLAGS=$(RUST_FLAGS)

all: 
	cargo build --release
	cp -f ../../../target/build/aead/rustcrypto_aes_256_blake3/release/librustcrypto_aes_256_blake3.so $(LIB_DIR)/librustcrypto_aes_256_blake3.so

clean:
	cargo clean
