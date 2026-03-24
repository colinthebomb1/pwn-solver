CC = gcc
CFLAGS_RET2WIN = -fno-stack-protector -no-pie -z execstack -z norelro

all: ret2win_x64

ret2win_x64: ret2win.c
	$(CC) $(CFLAGS_RET2WIN) -o $@ $<

clean:
	rm -f ret2win_x64

.PHONY: all clean
