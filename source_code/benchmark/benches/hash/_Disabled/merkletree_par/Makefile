include ../../base.mk

C_FLAGS := $(C_FLAGS) -fopenmp
LIBS := -lssl -lcrypto -lgomp -lstdc++

all: $(BUILD_DIR)/merkletree_par.o $(BUILD_DIR)/merklehash_par.o $(LIB_DIR)/libmerklehash_par.so

$(BUILD_DIR)/merkletree_par.o: merkletree_par.cpp
	$(CC) $(C_FLAGS) -c $< -o $@ 
	
$(BUILD_DIR)/merklehash_par.o: merklehash_par.cpp ../hash.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libmerklehash_par.so: $(BUILD_DIR)/merkletree_par.o $(BUILD_DIR)/merklehash_par.o
	$(CC) $(LD_FLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f $(BUILD_DIR)/*.o $(LIB_DIR)/*.so
