CC = gcc
CFLAGS = -Wall -Werror -I.
#LIBS = -L. -lmincrypt
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
APP = imgheaderinsert

.PHONY: all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) -s $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(APP)
