include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/blake2s256.so

$(BUILD_DIR)/blake2s256.o: blake2s256.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/blake2s256.so: $(BUILD_DIR)/blake2s256.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/blake2s256.o $(LIB_DIR)/blake2s256.so
