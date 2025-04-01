CC = gcc
CFLAGS = -Wall -g
LDLIBS += -lpcap

TARGET = arp-spoof

SRCS = function.cpp main.cpp
OBJS = $(SRCS:.cpp=.o)
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)  # TAB 사용

clean:
	rm -f $(TARGET) $(OBJS)  # TAB 사용

