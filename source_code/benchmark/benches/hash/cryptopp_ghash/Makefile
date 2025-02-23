include ../../base.mk

LIBS := -lcryptopp

all: $(LIB_DIR)/cryptopp_ghash.so

$(BUILD_DIR)/cryptopp_ghash.o: cryptopp_ghash.cpp ../hash.hpp 
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/cryptopp_ghash.so: $(BUILD_DIR)/cryptopp_ghash.o
	$(CC) $(LD_FLAGS) $< -o $@ $(LIBS)
	
clean:
	rm $(LIB_DIR)/cryptopp_ghash.so $(BUILD_DIR)/cryptopp_ghash.o
