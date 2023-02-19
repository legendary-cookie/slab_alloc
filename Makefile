all: slab
	./slab

slab: main.c
	gcc -g main.c -o slab
