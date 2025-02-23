include ../../base.mk

all: $(LIB_DIR)/libchacha20.so

$(BUILD_DIR)/chacha20.o: chacha20.cpp ChaCha20.h ../encryption.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libchacha20.so: $(BUILD_DIR)/chacha20.o
	$(CC) $(LD_FLAGS) $< -o $@
