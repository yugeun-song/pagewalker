CC = gcc
CFLAGS = -Wall -O2
TARGET = pagewalker
SRC = main.c

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	mv $(TARGET) ../bin/user/

clean:
	rm -f ../bin/user/$(TARGET)
