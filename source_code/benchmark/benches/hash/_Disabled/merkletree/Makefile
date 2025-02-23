include ../../base.mk

LIBS := -lssl -lcrypto

all: $(BUILD_DIR)/merkletree.o $(BUILD_DIR)/merklehash.o $(LIB_DIR)/libmerklehash.so

$(BUILD_DIR)/merkletree.o: merkletree.cpp
	$(CC) $(C_FLAGS) -c $< -o $@
	
$(BUILD_DIR)/merklehash.o: merklehash.cpp ../hash.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libmerklehash.so: $(BUILD_DIR)/merkletree.o $(BUILD_DIR)/merklehash.o
	$(CC) $(LD_FLAGS) $^ -o $@ $(LIBS)
