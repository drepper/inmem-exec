CC =gcc
CXX = g++
LD = ld
CXXFLAGS = -std=gnu++2a -Wall -Og -g
LIBS = -lelf
SHELL = /bin/bash

program = inmem-exec

all: $(program)

$(program): $(program).cc
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

asm-hello-x86_64.o: asm-hello-x86_64.S
	$(CC) -c -o $@ $< -nostdlib -nostartfiles -Wl,--build-id=none -static -mno-needed
asm-hello-x86_64: asm-hello-x86_64.o
	$(LD) -o $@ $< -static

run: $(program)
	./$(program)

check: $(program)
	./$(program) | cmp <(echo hello world) -

clean:
	rm $(program)

.PHONY: all run check clean
