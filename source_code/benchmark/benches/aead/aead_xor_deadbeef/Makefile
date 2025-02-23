include ../../base.mk

all: $(LIB_DIR)/libaead_xor_deadbeef.so

$(BUILD_DIR)/aead_xor_deadbeef.o: aead_xor_deadbeef.cpp ../aead.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libaead_xor_deadbeef.so: $(BUILD_DIR)/aead_xor_deadbeef.o
	$(CC) $(LD_FLAGS) $< -o $@

clean:
	rm $(BUILD_DIR)/*.so $(BUILD_DIR)/*.o $(LIB_DIR)/libaead_xor_deadbeef.so


