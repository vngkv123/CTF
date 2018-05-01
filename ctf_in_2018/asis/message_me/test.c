#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
	srand(1);
	for(int i = 0; i < 0x30; i++){
		printf("%#x, ", rand() % 10);
	}
	puts("");
}
