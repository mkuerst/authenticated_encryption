include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/sha3_512.so

$(BUILD_DIR)/sha3_512.o: sha3_512.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/sha3_512.so: $(BUILD_DIR)/sha3_512.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/sha3_512.o $(LIB_DIR)/sha3_512.so
