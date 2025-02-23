# Makefile for building and running the benchmark (separately)

# TODO: Change to arch of server
export RUSTFLAGS=-C target-cpu=native

all:
# Build the benchmark:
#	echo $$RUSTFLAGS
	cargo build --release --benches

# Create directory for output:
	mkdir -p ./target/output/
	
# Clear out in case make got rerun without a make clean first:
	rm -rf ./target/output/*

# Create ./target/output directory and put every file we need into there:
	cp ./target/release/deps/* ./target/output/
	ls ./target/output/ -1 | grep -v 'my_benchmark' | awk '{print "./target/output/"$$0}' | xargs --no-run-if-empty rm -f
	ls ./target/output/ -1 | grep '\.d' | awk '{print "./target/output/"$$0}' | xargs --no-run-if-empty rm -f

# Remove random characters after filename:
	mv ./target/output/my_benchmark-* ./target/output/my_benchmark

# Copy over the dynamic libraries for the benchmark:
	mkdir -p ./target/output/target/dynlibs/
	cp -r ./target/dynlibs/* ./target/output/target/dynlibs/

# Copy config file:
	cp ./config_bench.toml ./target/output/config_bench.toml

# Copy in Makefile for convenience:
	cp ./Makefile ./target/output/Makefile

# Create directory for libraries:
	mkdir ./target/output/libs
# Copy libcrypto++:
	dpkg -L libcrypto++-dev | grep "\+\+\.so" | xargs -I % cp % ./target/output/libs/libcrypto++.so
	ln ./target/output/libs/libcrypto++.so ./target/output/libs/libcryptopp.so
	ln ./target/output/libs/libcrypto++.so ./target/output/libs/libcrypto++.so.8
	ln ./target/output/libs/libcrypto++.so ./target/output/libs/libcryptopp.so.8
#	dpkg -L libcrypto++-dev | grep "pp\.so" | xargs -I % cp % ./target/output/libs/libcryptopp.so
# Copy ssl & crypto:
	dpkg -L libssl-dev | grep "\.so" | xargs -I %0 bash -c 'cp %0 ./target/output/libs/$$(basename %0)' bash



run:
	LD_LIBRARY_PATH=./libs/ ./my_benchmark --bench 2>&1 | tee benchmark_output_$(shell date +%Y-%0m-%0d-%H%M).txt
#	./target/output/my_benchmark --bench




clean:
	cargo clean
