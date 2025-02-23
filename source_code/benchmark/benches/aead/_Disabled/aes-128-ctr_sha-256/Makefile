include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/aes-128-ctr_sha-256.so

$(BUILD_DIR)/aes-128-ctr_sha-256.o: aes-128-ctr_sha-256.c
	$(CC) $(C_FLAGS) -c -o $@ $<


$(LIB_DIR)/aes-128-ctr_sha-256.so: $(BUILD_DIR)/aes-128-ctr_sha-256.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes-128-ctr_sha-256.o $(LIB_DIR)/aes-128-ctr_sha-256.so
