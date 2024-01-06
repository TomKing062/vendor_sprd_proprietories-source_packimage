CC = gcc
CFLAGS = -Wall -Icommon/pk1/inc -Icommon/rsa/inc -Icommon/sha256/inc -Icommon/verify/inc
ifeq ($(VB2048), 1)
    CFLAGS += -DVBMETA_USE_2048=1
else
    CFLAGS += -DVBMETA_USE_2048=0
endif
LIBS = -lcrypto -lssl -ldl
file_list := $(wildcard *.c)
file_list += $(wildcard $(CURDIR)/common/pk1/src/*.c)
file_list += $(wildcard $(CURDIR)/common/rsa/src/*.c)
file_list += $(wildcard $(CURDIR)/common/sha256/src/*.c)
file_list += $(wildcard $(CURDIR)/common/verify/src/*.c)
OBJS = $(file_list:.c=.o)
APP = sprd_sign

.PHONY: all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) -s $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(APP)
