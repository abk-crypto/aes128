CFLAGS = -std=c11 -Wall -Wextra -g -O2
CPPFLAGS = -Iinclude -DDEBUG
LDFLAGS = -lm

all : aes128

aes128: main.o aes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

main.o: src/main.c include/aes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

aes.o: src/aes.c include/aes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

clean:
	@rm -f *.o aes128