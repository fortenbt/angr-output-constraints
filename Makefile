CC := gcc

.PHONY: all clean

test: test.c

clean:
	rm -f test
