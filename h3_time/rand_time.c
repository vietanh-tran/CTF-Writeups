#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
int main(void)
{
	uint32_t rando;

	srand(time(0));
	rando = rand();

	printf("%u", rando);
	return 0;
}