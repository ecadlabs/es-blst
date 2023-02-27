SRC = ../blst/src/server.c misc.c

INCLUDE = -I../blst/src \
	-I../blst/bindings

OUT = ../dist/blst.wasm

CFLAGS = --target=wasm32 -D__BLST_NO_ASM__ -O2 -mbulk-memory -nostdlib -Wl,--no-entry -Wl,--export-all

all: $(OUT)

$(OUT): $(SRC)
	mkdir -p $(dir $@)
	clang $(CFLAGS) $(INCLUDE) -o $@ $^
