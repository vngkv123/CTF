#include <stdio.h>
#include <stdlib.h>

int main(){
	char *p1 = malloc(0x60);
	char *p2 = malloc(0x60);
	char *p3 = malloc(0x60);
	char *p4 = malloc(0x60);
	free(p1);
	free(p2);
	free(p3);
	free(p4);
	malloc(0x60);
	malloc(0x60);
	malloc(0x60);
	malloc(0x60);
}
