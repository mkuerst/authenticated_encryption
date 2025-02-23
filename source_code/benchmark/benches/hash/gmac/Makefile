
# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -fPIC -O3 -march=native -c
LDFLAGS := -shared
LIBS := -lssl -lcrypto

BUILD_DIR := ./
LIB_DIR := ./

all: $(LIB_DIR)/gmac.so

$(BUILD_DIR)/gmac.o: gmac.c
	$(CC) $(CFLAGS) -o $@ -fPIC $< $(LIBS)

$(LIB_DIR)/gmac.so: $(BUILD_DIR)/gmac.o
	$(CC) $(LDFLAGS) -o $@ -fPIC $< $(LIBS)

clean:
	rm -f $(BUILD_DIR)/gmac.o $(LIB_DIR)/gmac.so