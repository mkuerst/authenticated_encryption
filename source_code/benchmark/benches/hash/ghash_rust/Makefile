include ../../base.mk

export RUSTFLAGS=$(RUST_FLAGS)
# export RUSTFLAGS=-Ctarget-cpu=sandybridge
# export RUSTFLAGS=

all:
#	cargo build
#	cp -f ../../../target/build/hash/ghash_rust/debug/libghash_rust.so $(LIB_DIR)/libghash_rust.so
	echo "RUST_FLAGS:" $$RUSTFLAGS
	cargo build --release
	cp -f ../../../target/build/hash/ghash_rust/release/libghash_rust.so $(LIB_DIR)/libghash_rust.so

clean:
	cargo clean
