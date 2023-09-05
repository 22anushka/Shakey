// ```
// @author: Anushka Sivakumar, Asmi Sriwastawa
// ```
// Throughput

#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

#define rotate_left(x,n,w) (((x) >> (w - (n))) | ((x) << (n)))
#define rotate_right(x,n,w) (((x) << (w - (n))) | ((x) >> (n)))

double tt = 0;
clock_t start, end;

void TIMESTWO(uint32_t *q) {
	if(!(*q & 131072)) {
		*q = rotate_left(*q, 1, 32);
	}
	else {
		*q = rotate_left(*q, 1, 32);
		*q = *q ^ 135;
	}
}

uint16_t* Round_Key_Generator(uint16_t* key) {
	uint32_t* k = (uint32_t*)key;

	TIMESTWO(&k[0]);
	TIMESTWO(&k[1]);
	TIMESTWO(&k[2]);
	TIMESTWO(&k[3]);

	k[0] = rotate_left(k[0], 16, 32);
	k[1] = rotate_left(k[1], 16, 32);
	k[2] = rotate_left(k[2], 16, 32);
	k[3] = rotate_left(k[3], 16, 32);

	key = (uint16_t*)k;

	return key;
}

uint64_t Shadow_Encrypt_64(uint16_t key_schedule[8], uint16_t plaintext[4]) {

    uint16_t l0 = plaintext[3]; //points to 3B 72
    uint16_t l1 = plaintext[2]; //points to 65 74
    uint16_t r0 = plaintext[1]; //points to 74 75
    uint16_t r1 = plaintext[0]; //points to 43 2D
    uint16_t temp;

    uint16_t *round_key = key_schedule;
    for(uint8_t i = 0; i < 32; i++) { 
        round_key = Round_Key_Generator(round_key);

	uint16_t state0 = (rotate_left(l0,1,16)&rotate_left(l0,7,16))^(l1)^(rotate_left(l0,2,16))^round_key[1];
        uint16_t state1 = (rotate_left(r0,1,16)&rotate_left(r0,7,16))^(r1)^(rotate_left(r0,2,16))^round_key[3];

	
        l1 = (rotate_left(state0,1,16)&rotate_left(state0,7,16))^(l0)^rotate_left(state0,2,16)^round_key[5];
        r1 = (rotate_left(state1,1,16)&rotate_left(state1,7,16))^(r0)^rotate_left(state1,2,16)^round_key[7];
	l0 = state1;
	r0 = state0;
    }

    temp = l0;
    l0 = r0;
    r0 = temp;

    /*printf("0x%04x", (unsigned int)l0);
    printf("%04x", (unsigned int)l1);
    printf("%04x", (unsigned int)r0);
    printf("%04x\n", (unsigned int)r1);*/

    uint16_t cb[] = {l0, l1, r0, r1};
    uint64_t C = 0;
    for(int j = 0; j < 4; j++)
    {
    	if(j != 0)
        	C <<= 16;
    	C ^= cb[j];
    }
    return C;
}

uint64_t rand_uint64_slow(void)
{
  uint64_t r = 0;
  for (int i=0; i<64; i++)
  {
    r <<= 1;
    r ^= rand()%2;
  }
  return r;
}

int ae[100][64];

int main()
{
	for(int i = 0; i < 100; i++)
	{
		uint64_t P = rand_uint64_slow();
		uint64_t K = rand_uint64_slow();

		uint16_t shadow128_64_plain[4];
		uint16_t shadow128_64_key[8];
		for(int j = 0; j < 4; j++)
		{
			shadow128_64_plain[j] = (uint16_t)(P >> (j*16));
		}
		for(int j = 0; j < 8; j++)
		{
			shadow128_64_key[j] = (uint16_t)(K >> (j*16));
		}
		start = clock();
		Shadow_Encrypt_64(shadow128_64_key, shadow128_64_plain);
		end = clock();
		tt += ((double)(end-start))/CLOCKS_PER_SEC;
	}

	printf("%lf Mbps\n", 6400/tt/1000000);
}