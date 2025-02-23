include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_192_cbc.so

$(BUILD_DIR)/aes_192_cbc.o: aes_192_cbc.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_192_cbc.so: $(BUILD_DIR)/aes_192_cbc.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_192_cbc.o $(LIB_DIR)/aes_192_cbc.so

.PHONY: clean all
