include ../../base.mk

LIBS := -lcryptopp

all: $(LIB_DIR)/libcryptopp.so

$(BUILD_DIR)/cryptopp_gcm.o: cryptopp_gcm.cpp ../aead.hpp 
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libcryptopp.so: $(BUILD_DIR)/cryptopp_gcm.o
	$(CXX) $(LD_FLAGS) $< -o $@ $(LIBS)

clean:
	rm $(LIB_DIR)/libcryptopp.so $(BUILD_DIR)/cryptopp_gcm.o
