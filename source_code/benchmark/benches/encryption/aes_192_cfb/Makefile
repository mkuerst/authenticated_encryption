include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_192_cfb.so

$(BUILD_DIR)/aes_192_cfb.o: aes_192_cfb.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_192_cfb.so: $(BUILD_DIR)/aes_192_cfb.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_192_cfb.o $(LIB_DIR)/aes_192_cfb.so

.PHONY: clean
