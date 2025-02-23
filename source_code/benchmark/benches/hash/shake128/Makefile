include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/shake128.so

$(BUILD_DIR)/shake128.o: shake128.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/shake128.so: $(BUILD_DIR)/shake128.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/shake128.o $(LIB_DIR)/shake128.so
