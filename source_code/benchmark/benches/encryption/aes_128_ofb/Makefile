include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_128_ofb.so

$(BUILD_DIR)/aes_128_ofb.o: aes_128_ofb.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_128_ofb.so: $(BUILD_DIR)/aes_128_ofb.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_128_ofb.o $(LIB_DIR)/aes_128_ofb.so

.PHONY: clean
