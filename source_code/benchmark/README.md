## Commands to create a shared library:
# Hash:
g++ -c -O3 -o xor256.o xor256.cpp && gcc -shared -o xor256.so xor256.o
# Encryption:
g++ -c -O3 -o xor_deadbeef.o xor_deadbeef.cpp && gcc -shared -o xor_deadbeef.so xor_deadbeef.o
# AEAD:
g++ -c -O3 -o aead_xor_deadbeef.o aead_xor_deadbeef.cpp && gcc -shared -o aead_xor_deadbeef.so aead_xor_deadbeef.o


# Commands to run specific hashing/encryption/AEAD functions:
cargo run -- [input_size in bytes] {functions matching these will be tested}
e.g.:
cargo run -- 2048 cha xor

# Commands to run benchmarks:
cargo bench


# Clean up build files
cargo clean


# Results can be found:
- Printed to terminal
- ./target/criterion/report/index.html

