all: pcapTest.c
	gcc -g -Wall -o pcapTest pcapTest.c -lpcap
clean:
	rm -rf *.o pcapTest
