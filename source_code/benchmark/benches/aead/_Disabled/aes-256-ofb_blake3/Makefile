include ../../base.mk

LIBS := -lssl -lcrypto
MISC := blake3.c blake3_dispatch.c blake3_portable.c blake3_sse2_x86-64_unix.S blake3_sse41_x86-64_unix.S blake3_avx2_x86-64_unix.S blake3_avx512_x86-64_unix.S ../aead.h

SRCS := $(wildcard *.c) $(wildcard *.S)
OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(filter %.c, $(SRCS))) $(patsubst %.S, $(BUILD_DIR)/%.o, $(filter %.S, $(SRCS)))

all: $(LIB_DIR)/aes-256-ofb_blake3.so

$(BUILD_DIR)/%.o: ./%.c
	$(CC) $(C_FLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: ./%.S
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/aes-256-ofb_blake3.so: $(BUILD_DIR)/aes-256-ofb_blake3.o $(OBJS)
	$(CC) $(LD_FLAGS) $^ $(LIBS) -o $@
