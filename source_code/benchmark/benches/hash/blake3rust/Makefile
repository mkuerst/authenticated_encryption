include ../../base.mk

export RUSTFLAGS=$(RUST_FLAGS)

all:
	cargo build --release
	cp -f ../../../target/build/hash/blake3rust/release/libblake3rust.so $(LIB_DIR)/blake3rust.so

clean:
	cargo clean
