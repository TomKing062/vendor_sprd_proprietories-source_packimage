CC = gcc
CFLAGS = -Wall -Werror -I.
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
APP = generate_sign_script_for_vbmeta

.PHONY: all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) -s $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(APP)
