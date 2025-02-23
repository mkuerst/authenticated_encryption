include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_192_ofb.so

$(BUILD_DIR)/aes_192_ofb.o: aes_192_ofb.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_192_ofb.so: $(BUILD_DIR)/aes_192_ofb.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_192_ofb.o $(LIB_DIR)/aes_192_ofb.so

.PHONY: clean
