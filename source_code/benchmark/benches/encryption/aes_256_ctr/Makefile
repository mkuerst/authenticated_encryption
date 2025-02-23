include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes_256_ctr.so

$(BUILD_DIR)/aes_256_ctr.o: aes_256_ctr.c
	$(CC) $(C_FLAGS) -o $@ -c $< 

$(LIB_DIR)/aes_256_ctr.so: $(BUILD_DIR)/aes_256_ctr.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_256_ctr.o $(LIB_DIR)/aes_256_ctr.so

.PHONY: clean
