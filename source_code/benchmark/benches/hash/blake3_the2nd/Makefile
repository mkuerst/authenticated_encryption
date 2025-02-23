include ../../base.mk

MISC := blake3.c blake3_dispatch.c blake3_portable.c blake3_sse2_x86-64_unix.S blake3_sse41_x86-64_unix.S blake3_avx2_x86-64_unix.S blake3_avx512_x86-64_unix.S ../hash.hpp

SRCS := $(wildcard *.c) $(wildcard *.S)
OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(filter %.c, $(SRCS))) $(patsubst %.S, $(BUILD_DIR)/%.o, $(filter %.S, $(SRCS)))

all: $(LIB_DIR)/blake3_the2nd.so

$(BUILD_DIR)/%.o: ./%.c
	$(CC) $(C_FLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: ./%.S
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/blake3_the2nd.so: $(BUILD_DIR)/blake3_the2nd.o $(OBJS)
	$(CC) $(LD_FLAGS) $^ -o $@
