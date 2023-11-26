CC = gcc
AR = ar
CFLAGS = -Wall -Werror -I.

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
LIB = libmincrypt.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB)
