#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

int main (void)
{
	srand(time(0));

	for (int i = 0; i < 0x32; i++)
		printf("%d\n", rand() % 100);
	
	return 0;
}