include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/sha3_384.so

$(BUILD_DIR)/sha3_384.o: sha3_384.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/sha3_384.so: $(BUILD_DIR)/sha3_384.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/sha3_384.o $(LIB_DIR)/sha3_384.so
