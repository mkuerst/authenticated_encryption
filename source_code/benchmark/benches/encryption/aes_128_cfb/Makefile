include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_128_cfb.so

$(BUILD_DIR)/aes_128_cfb.o: aes_128_cfb.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_128_cfb.so: $(BUILD_DIR)/aes_128_cfb.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_128_cfb.o $(LIB_DIR)/aes_128_cfb.so

.PHONY: clean
