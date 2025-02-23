
# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -fPIC -O3 -march=native -c
LDFLAGS := -shared
LIBS := -lssl -lcrypto

BUILD_DIR := ./
LIB_DIR := ./

all: $(LIB_DIR)/aes_192_cfb8.so

$(BUILD_DIR)/aes_192_cfb8.o: aes_192_cfb8.c
	$(CC) $(CFLAGS) -o $@ -fPIC $< $(LIBS)

$(LIB_DIR)/aes_192_cfb8.so: $(BUILD_DIR)/aes_192_cfb8.o
	$(CC) $(LDFLAGS) -o $@ -fPIC $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/aes_192_cfb8.o $(LIB_DIR)/aes_192_cfb8.so