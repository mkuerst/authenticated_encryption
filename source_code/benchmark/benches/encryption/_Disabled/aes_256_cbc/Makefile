include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_256_cbc.so

$(BUILD_DIR)/aes_256_cbc.o: aes_256_cbc.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_256_cbc.so: $(BUILD_DIR)/aes_256_cbc.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_256_cbc.o $(LIB_DIR)/aes_256_cbc.so

.PHONY: clean
