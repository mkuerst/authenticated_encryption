include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/sha_384.so

$(BUILD_DIR)/sha_384.o: sha_384.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/sha_384.so: $(BUILD_DIR)/sha_384.o
	$(CC) $(LD_FLAGS) -o $@ -fPIC $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/sha_384.o $(LIB_DIR)/sha_384.so
