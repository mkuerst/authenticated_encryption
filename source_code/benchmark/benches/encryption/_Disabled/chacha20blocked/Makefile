# Makefile for building a shared library

# Compiler and flags
CC := gcc
CFLAGS := -Wall -fPIC -O3 -march=native
LDFLAGS := -shared

BUILD_DIR := ./
LIB_DIR := ./

all: $(LIB_DIR)/libchacha20blocked.so

$(BUILD_DIR)/chacha20blocked.o: chacha20blocked.cpp ChaCha20.h ../encryption.hpp
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/libchacha20blocked.so: $(BUILD_DIR)/chacha20blocked.o
	$(CC) $(LDFLAGS) $< -o $@
