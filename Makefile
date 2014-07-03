all: bpftest
	./bpftest

bpftest: bpftest.c
	gcc -I. -Wall bpftest.c -o bpftest
