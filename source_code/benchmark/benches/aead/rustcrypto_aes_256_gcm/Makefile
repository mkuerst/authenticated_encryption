include ../../base.mk

export RUSTFLAGS=$(RUST_FLAGS)

all: 
	cargo build --release
	cp -f ../../../target/build/aead/rustcrypto_aes_256_gcm/release/librustcrypto_aes_256_gcm.so $(LIB_DIR)/librustcrypto_aes_256_gcm.so

clean:
	cargo clean
