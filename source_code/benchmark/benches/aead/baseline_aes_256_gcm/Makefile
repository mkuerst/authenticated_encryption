include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_256_gcm.so

$(BUILD_DIR)/aes_256_gcm.o: aes_256_gcm.c
	$(CC) $(C_FLAGS) -c -o $@ -fPIC $<


$(LIB_DIR)/aes_256_gcm.so: $(BUILD_DIR)/aes_256_gcm.o
	$(CC) $(LD_FLAGS) -o $@ -fPIC $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_256_gcm.o $(LIB_DIR)/aes_256_gcm.so
