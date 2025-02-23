include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/sha_256.so

$(BUILD_DIR)/sha_256.o: sha_256.c
	$(CC) $(C_FLAGS) -c -o $@  $<

$(LIB_DIR)/sha_256.so: $(BUILD_DIR)/sha_256.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/sha_256.o $(LIB_DIR)/sha_256.so
