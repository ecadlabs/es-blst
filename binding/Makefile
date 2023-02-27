SRC = ../blst/src/server.c misc.c

INCLUDE = -I../blst/src \
	-I../blst/bindings

OUT = ../dist/blst.wasm

CFLAGS = --target=wasm32 -D__BLST_NO_ASM__ -O2 -mbulk-memory -nostdlib -Wl,--no-entry -Wl,--export-all
LLVMPATH = /opt/homebrew/opt/llvm/bin

all: $(OUT)

$(OUT): $(SRC)
	mkdir -p $(dir $@)
	PATH="$(LLVMPATH):$(PATH)" clang $(CFLAGS) $(INCLUDE) -o $@ $^
