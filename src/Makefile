CC = gcc
C_FLAGS = -Wall
INCLUDE =
LIBS = -lpcap

SRCS := $(wildcard *.c)

TARGET := $(patsubst %.c, %, $(SRCS))
OBJDIR = .

.c:
	$(CC) $(C_FLAGS) -o $@ $< $(INCLUDE) $(LIBS)

all: $(TARGET) clean
clean:
	rm -rf *.o