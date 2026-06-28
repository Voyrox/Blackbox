CXX = g++
CXXFLAGS = -Wall -std=c++17

all: build/main

build/main: src/main.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $< -o $@

run: build/main
	./build/main

clean:
	rm -rf build

.PHONY: all run clean
