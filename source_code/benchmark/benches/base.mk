BUILD_DIR := .
LIB_DIR := .

ARCH := native
RUST_ARCH := native

# RUST_FLAGS := 
RUST_FLAGS := -C target-cpu=$(RUST_ARCH)

# Disable AVX512 by swapping the comments on the next two lines
# AVX512 := -mavx512f
AVX512 :=

ISA_EXT := -mavx -mavx2 -mfma $(AVX512)
OPTS := -march=$(ARCH) $(ISA_EXT) -O3 -flto 

RUST_TARGET := $(ARCH)
RUST_FEATURES :=

# DEBUG := -g -fsanitize=address,bounds,bounds-strict,alignment,undefined
# DEBUG := -g -fsanitize=address,bounds,bounds-strict,alignment,undefined -ldl
DEBUG :=

C_FLAGS := $(OPTS) -fPIC $(DEBUG) -Wall -Wextra
CXX_FLAGS := $(OPTS) -fPIC $(DEBUG) -Wall -Wextra
LD_FLAGS := -shared

CC := gcc
CXX := g++
