include ../../base.mk

all: $(LIB_DIR)/libxor256.so

$(BUILD_DIR)/xor256.o: xor256.cpp ../hash.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libxor256.so: $(BUILD_DIR)/xor256.o
	$(CC) $(LD_FLAGS) $? -o $@
