include ../../base.mk

ifeq (-mavx512f,$(AVX512))
	COPT := -DUSE_AVX512
else
	COPT := -DUSE_AVX2
endif

C_FLAGS := $(C_FLAGS) $(COPT)

SRCS := entry.cpp chacha20.c chacha20_avx2.c chacha20_sse2.c chacha20_avx512.c
OBJS := $(patsubst %, $(BUILD_DIR)/%, entry.o chacha20.o chacha20_avx2.o chacha20_sse2.o chacha20_avx512.o)

all: $(LIB_DIR)/libchacha20_simd.so
	echo $(COPT)
	echo $(CXX_FLAGS)

$(BUILD_DIR)/%.o: %.c chacha20.h
	$(CC) $(C_FLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.cpp chacha20.h ../encryption.hpp
	$(CC) $(C_FLAGS) -c $< -o $@

$(LIB_DIR)/libchacha20_simd.so: $(OBJS)
	$(CC) $(LD_FLAGS) $^ -o $@

clean:
	rm -f $(BUILD_DIR)/*.o $(LIB_DIR)/libchacha20_simd.so

check:
	@echo $(COPT)

.PHONY: clean all check
