include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_192_cfb128.so

$(BUILD_DIR)/aes_192_cfb128.o: aes_192_cfb128.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_192_cfb128.so: $(BUILD_DIR)/aes_192_cfb128.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_192_cfb128.o $(LIB_DIR)/aes_192_cfb128.so

.PHONY: clean all
