include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/sha_512.so

$(BUILD_DIR)/sha_512.o: sha_512.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/sha_512.so: $(BUILD_DIR)/sha_512.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/sha_512.o $(LIB_DIR)/sha_512.so
