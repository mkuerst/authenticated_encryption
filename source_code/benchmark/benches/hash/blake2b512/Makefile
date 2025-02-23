include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/blake2b512.so

$(BUILD_DIR)/blake2b512.o: blake2b512.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/blake2b512.so: $(BUILD_DIR)/blake2b512.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/blake2b512.o $(LIB_DIR)/blake2b512.so
