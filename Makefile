CXX = g++
CXXFLAGS = -std=gnu++2a -Wall -Og -g
LIBS = -lelf
SHELL = /bin/bash

program = inmem-exec

all: $(program)

$(program): $(program).cc
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

run: $(program)
	./$(program)

check: $(program)
	./$(program) | cmp <(echo hello world) -

clean:
	rm $(program)

.PHONY: all run check clean
