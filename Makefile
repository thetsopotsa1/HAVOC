# HAVOC 3.0 Makefile
# Compile with: make
# Clean with: make clean

CC = gcc
CFLAGS = -O2 -Wall -Wextra
LIBS = -lcrypto
TARGET = havoc
SOURCE = havoc.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)
	rm -rf evidence/

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Development targets
test: $(TARGET)
	@echo "Testing compilation..."
	@./$(TARGET) || echo "Usage: ./$(TARGET) <target-ip> [port=8080]"

debug: $(SOURCE)
	$(CC) -g -DDEBUG -Wall -Wextra -o $(TARGET)-debug $(SOURCE) $(LIBS)

# Quick build for different architectures
static: $(SOURCE)
	$(CC) $(CFLAGS) -static -o $(TARGET)-static $(SOURCE) $(LIBS)

# Help target
help:
	@echo "HAVOC 3.0 Build System"
	@echo "====================="
	@echo "Available targets:"
	@echo "  all     - Build the main executable (default)"
	@echo "  clean   - Remove built files and evidence directory"
	@echo "  install - Install to /usr/local/bin"
	@echo "  test    - Test compilation"
	@echo "  debug   - Build with debug symbols"
	@echo "  static  - Build static binary"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Usage after build:"
	@echo "  ./$(TARGET) <target-ip> [port=8080]"
	@echo ""
	@echo "Dependencies: OpenSSL development libraries"
	@echo "  Ubuntu/Debian: apt-get install libssl-dev"
	@echo "  CentOS/RHEL:   yum install openssl-devel"
	@echo "  macOS:         brew install openssl"