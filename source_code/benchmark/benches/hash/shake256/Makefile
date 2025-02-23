include ../../base.mk

LIBS := -lssl -lcrypto

all: $(LIB_DIR)/shake256.so

$(BUILD_DIR)/shake256.o: shake256.c
	$(CC) $(C_FLAGS) -c -o $@ $<

$(LIB_DIR)/shake256.so: $(BUILD_DIR)/shake256.o
	$(CC) $(LD_FLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/shake256.o $(LIB_DIR)/shake256.so
