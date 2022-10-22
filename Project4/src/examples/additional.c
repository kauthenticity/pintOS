#include <syscall.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]){
	int arr[4];
	for(int i=1; i<argc; i++){
		arr[i-1] = atoi(argv[i]);
	}
	int fibo = fibonacci(arr[0]);
	int max = max_of_four_int(arr[0], arr[1], arr[2], arr[3]);

	printf("%d %d\n", fibo, max);
	return 0;
}
