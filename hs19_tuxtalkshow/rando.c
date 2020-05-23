#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

int main(void)
{
	uint32_t rando;
	int32_t buf[6] = {0x79, 0x12c97f, 0x135f0f8, 0x74acbc6, 0x56c614e, 0xffffffe2};
	int32_t sol;
	srand(time(0));

	sol = 0;
	for (int i = 0; i < 6; i++) {
		buf[i] -= rand() % 10 - 1;
		sol += buf[i];
	}
	printf("%d", sol);

	return 0;
}