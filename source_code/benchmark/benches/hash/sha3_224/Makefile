include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/sha3_224.so

$(BUILD_DIR)/sha3_224.o: sha3_224.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/sha3_224.so: $(BUILD_DIR)/sha3_224.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/sha3_224.o $(LIB_DIR)/sha3_224.so
