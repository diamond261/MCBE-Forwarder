# Makefile for Port Forwarder

CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
TARGET = forwarder
SRC = forwarder.cpp

# Debug build
DEBUG_FLAGS = -g -DDEBUG

all: $(TARGET)

$(TARGET): $(SRC) forwarder.hpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

debug: $(SRC) forwarder.hpp
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) -o $(TARGET)_debug $(SRC)

clean:
	rm -f $(TARGET) $(TARGET)_debug

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all debug clean install