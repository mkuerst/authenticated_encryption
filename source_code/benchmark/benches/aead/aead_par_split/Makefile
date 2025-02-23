include ../../base.mk

export RUSTFLAGS=$(RUST_FLAGS)

# GNU parallel?
# CARGO_TARGET_DIR=../../../target/build/aead/aead_par_split_xor_deadbeef/ cargo build --release --features xor_deadbeef
# CARGO_TARGET_DIR=../../../target/build/aead/aead_par_split_aes_256_gcm/ cargo build --release --features aes_256_gcm

all: 
# $(LIB_DIR)/src/lib.rs
	cargo build --release --features xor_deadbeef
	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_xor_deadbeef.so
	cargo build --release --features aes_256_gcm
	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_aes_256_gcm.so
	cargo build --release --features cryptopp_gcm
	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_cryptopp_gcm.so
	cargo build --release --features rustcrypto_aes_256_gcm
	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_rustcrypto_aes_256_gcm.so
	cargo build --release --features rustcrypto_aes_256_blake3
	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_rustcrypto_aes_256_blake3.so
	
#	cargo build --release --features aes128ctr_sha256
#	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_aes128ctr_sha256.so
#	cargo build --release --features aes128ofb_sha256
#	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_aes128ofb_sha256.so
#	cargo build --release --features aes256ctr_sha256
#	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_aes256ctr_sha256.so
#	cargo build --release --features aes256ofb_sha256
#	cp -f ../../../target/build/aead/aead_par_split/release/libaead_par_split.so $(LIB_DIR)/aead_par_split_aes256ofb_sha256.so

clean:
	cargo clean
