include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/libmd5.so

$(BUILD_DIR)/md5.o: md5.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/libmd5.so: $(BUILD_DIR)/md5.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/md5.o $(LIB_DIR)/libmd5.so
