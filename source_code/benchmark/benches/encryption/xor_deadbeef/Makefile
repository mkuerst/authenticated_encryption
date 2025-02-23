include ../../base.mk

all: $(LIB_DIR)/libxor_deadbeef.so

$(BUILD_DIR)/xor_deadbeef.o: xor_deadbeef.cpp ../encryption.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libxor_deadbeef.so: $(BUILD_DIR)/xor_deadbeef.o
	$(CC) $(LD_FLAGS) $< -o $@

clean:
	rm -f $(BUILD_DIR)/xor_deadbeef.o $(LIB_DIR)/libxor_deadbeef.so

.PHONY: clean all
