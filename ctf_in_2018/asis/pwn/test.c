#include <stdio.h>
#include <unistd.h>

int main(){
	execveat(0, "/bin/sh", 0, 0, 0);
}
