#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef UINT32_C
    #define UINT32_C(c) c##UL
#endif

#define BLOCK_LEN 64
#define STATE_LEN 5

#define REVERSE_LONG(n) ((unsigned long) (((n & 0xFF) << 24) | \
                                          ((n & 0xFF00) << 8) | \
                                          ((n & 0xFF0000) >> 8) | \
                                          ((n & 0xFF000000) >> 24)))

void sha1_compress(const uint8_t block[64], uint32_t state[5]) {
	#define ROTL32(x, n)  (((0U + (x)) << (n)) | ((x) >> (32 - (n))))  // Assumes that x is uint32_t and 0 < n < 32
	
	#define LOADSCHEDULE(i)  \
		schedule[i] = (uint32_t)block[i * 4 + 0] << 24  \
		            | (uint32_t)block[i * 4 + 1] << 16  \
		            | (uint32_t)block[i * 4 + 2] <<  8  \
		            | (uint32_t)block[i * 4 + 3] <<  0;
	
	#define SCHEDULE(i)  \
		temp = schedule[(i - 3) & 0xF] ^ schedule[(i - 8) & 0xF] ^ schedule[(i - 14) & 0xF] ^ schedule[(i - 16) & 0xF];  \
		schedule[i & 0xF] = ROTL32(temp, 1);
	
	#define ROUND0a(a, b, c, d, e, i)  LOADSCHEDULE(i)  ROUNDTAIL(a, b, e, ((b & c) | (~b & d))         , i, 0x5A827999)
	#define ROUND0b(a, b, c, d, e, i)  SCHEDULE(i)      ROUNDTAIL(a, b, e, ((b & c) | (~b & d))         , i, 0x5A827999)
	#define ROUND1(a, b, c, d, e, i)   SCHEDULE(i)      ROUNDTAIL(a, b, e, (b ^ c ^ d)                  , i, 0x6ED9EBA1)
	#define ROUND2(a, b, c, d, e, i)   SCHEDULE(i)      ROUNDTAIL(a, b, e, ((b & c) ^ (b & d) ^ (c & d)), i, 0x8F1BBCDC)
	#define ROUND3(a, b, c, d, e, i)   SCHEDULE(i)      ROUNDTAIL(a, b, e, (b ^ c ^ d)                  , i, 0xCA62C1D6)
	
	#define ROUNDTAIL(a, b, e, f, i, k)  \
		e = 0U + e + ROTL32(a, 5) + f + UINT32_C(k) + schedule[i & 0xF];  \
		b = ROTL32(b, 30);
	
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	
	uint32_t schedule[16];
	uint32_t temp;
	ROUND0a(a, b, c, d, e,  0)
	ROUND0a(e, a, b, c, d,  1)
	ROUND0a(d, e, a, b, c,  2)
	ROUND0a(c, d, e, a, b,  3)
	ROUND0a(b, c, d, e, a,  4)
	ROUND0a(a, b, c, d, e,  5)
	ROUND0a(e, a, b, c, d,  6)
	ROUND0a(d, e, a, b, c,  7)
	ROUND0a(c, d, e, a, b,  8)
	ROUND0a(b, c, d, e, a,  9)
	ROUND0a(a, b, c, d, e, 10)
	ROUND0a(e, a, b, c, d, 11)
	ROUND0a(d, e, a, b, c, 12)
	ROUND0a(c, d, e, a, b, 13)
	ROUND0a(b, c, d, e, a, 14)
	ROUND0a(a, b, c, d, e, 15)
	ROUND0b(e, a, b, c, d, 16)
	ROUND0b(d, e, a, b, c, 17)
	ROUND0b(c, d, e, a, b, 18)
	ROUND0b(b, c, d, e, a, 19)
	ROUND1(a, b, c, d, e, 20)
	ROUND1(e, a, b, c, d, 21)
	ROUND1(d, e, a, b, c, 22)
	ROUND1(c, d, e, a, b, 23)
	ROUND1(b, c, d, e, a, 24)
	ROUND1(a, b, c, d, e, 25)
	ROUND1(e, a, b, c, d, 26)
	ROUND1(d, e, a, b, c, 27)
	ROUND1(c, d, e, a, b, 28)
	ROUND1(b, c, d, e, a, 29)
	ROUND1(a, b, c, d, e, 30)
	ROUND1(e, a, b, c, d, 31)
	ROUND1(d, e, a, b, c, 32)
	ROUND1(c, d, e, a, b, 33)
	ROUND1(b, c, d, e, a, 34)
	ROUND1(a, b, c, d, e, 35)
	ROUND1(e, a, b, c, d, 36)
	ROUND1(d, e, a, b, c, 37)
	ROUND1(c, d, e, a, b, 38)
	ROUND1(b, c, d, e, a, 39)
	ROUND2(a, b, c, d, e, 40)
	ROUND2(e, a, b, c, d, 41)
	ROUND2(d, e, a, b, c, 42)
	ROUND2(c, d, e, a, b, 43)
	ROUND2(b, c, d, e, a, 44)
	ROUND2(a, b, c, d, e, 45)
	ROUND2(e, a, b, c, d, 46)
	ROUND2(d, e, a, b, c, 47)
	ROUND2(c, d, e, a, b, 48)
	ROUND2(b, c, d, e, a, 49)
	ROUND2(a, b, c, d, e, 50)
	ROUND2(e, a, b, c, d, 51)
	ROUND2(d, e, a, b, c, 52)
	ROUND2(c, d, e, a, b, 53)
	ROUND2(b, c, d, e, a, 54)
	ROUND2(a, b, c, d, e, 55)
	ROUND2(e, a, b, c, d, 56)
	ROUND2(d, e, a, b, c, 57)
	ROUND2(c, d, e, a, b, 58)
	ROUND2(b, c, d, e, a, 59)
	ROUND3(a, b, c, d, e, 60)
	ROUND3(e, a, b, c, d, 61)
	ROUND3(d, e, a, b, c, 62)
	ROUND3(c, d, e, a, b, 63)
	ROUND3(b, c, d, e, a, 64)
	ROUND3(a, b, c, d, e, 65)
	ROUND3(e, a, b, c, d, 66)
	ROUND3(d, e, a, b, c, 67)
	ROUND3(c, d, e, a, b, 68)
	ROUND3(b, c, d, e, a, 69)
	ROUND3(a, b, c, d, e, 70)
	ROUND3(e, a, b, c, d, 71)
	ROUND3(d, e, a, b, c, 72)
	ROUND3(c, d, e, a, b, 73)
	ROUND3(b, c, d, e, a, 74)
	ROUND3(a, b, c, d, e, 75)
	ROUND3(e, a, b, c, d, 76)
	ROUND3(d, e, a, b, c, 77)
	ROUND3(c, d, e, a, b, 78)
	ROUND3(b, c, d, e, a, 79)
	
	state[0] = 0U + state[0] + a;
	state[1] = 0U + state[1] + b;
	state[2] = 0U + state[2] + c;
	state[3] = 0U + state[3] + d;
	state[4] = 0U + state[4] + e;
}

void sha1_hash(const uint8_t message[], size_t len, uint32_t hash[STATE_LEN]) {
	hash[0] = UINT32_C(0x67452301);
	hash[1] = UINT32_C(0xEFCDAB89);
	hash[2] = UINT32_C(0x98BADCFE);
	hash[3] = UINT32_C(0x10325476);
	hash[4] = UINT32_C(0xC3D2E1F0);
	
	#define LENGTH_SIZE 8  // In bytes
	
	size_t off;
	for (off = 0; len - off >= BLOCK_LEN; off += BLOCK_LEN)
		sha1_compress(&message[off], hash);
	
	uint8_t block[BLOCK_LEN] = {0};
	size_t rem = len - off;
	if (rem > 0)
		memcpy(block, &message[off], rem);
	
	block[rem] = 0x80;
	rem++;
	if (BLOCK_LEN - rem < LENGTH_SIZE) {
		sha1_compress(block, hash);
		memset(block, 0, sizeof(block));
	}
	
	block[BLOCK_LEN - 1] = (uint8_t)((len & 0x1FU) << 3);
	len >>= 5;
    int i;
	for (i = 1; i < LENGTH_SIZE; i++, len >>= 8)
		block[BLOCK_LEN - 1 - i] = (uint8_t)(len & 0xFFU);
	sha1_compress(block, hash);
}

int hexStr2Arr(unsigned char* out, const char* in) {
    int out_len_max = 20;

    const int in_len = strlen(in);
    if (in_len % 2 != 0)
        return -1;

    const int out_len = out_len_max < (in_len / 2) ? out_len_max : (in_len / 2);

    int i;
    for (i = 0; i < out_len; i++) {
        char ch0 = in[2 * i];
        char ch1 = in[2 * i + 1];
        uint8_t nib0 = (ch0 & 0xF) + (ch0 >> 6) | ((ch0 >> 3) & 0x8);
        uint8_t nib1 = (ch1 & 0xF) + (ch1 >> 6) | ((ch1 >> 3) & 0x8);
        out[i] = (nib0 << 4) | nib1;
    }
    return out_len;
}

int baza_suma_de_control(char *cnp) {
    int val = (cnp[0] - '0') * 2;
    val += (cnp[1] - '0') * 7;
    val += (cnp[2] - '0') * 9;
    val += (cnp[3] - '0');
    val += (cnp[4] - '0') * 4;
    val += (cnp[5] - '0') * 6;
    val += (cnp[6] - '0') * 3;
    return val;
}

int find_cnp(int sex, int y, int m, int d, uint32_t isu[STATE_LEN]) {
    char cnp[14];
    static uint32_t state[STATE_LEN];
    int i, j, val, suma;
    cnp[0] = 0;

    sprintf(cnp, "%i%02i%02i%02i", sex, y, m, d);

    int baza = baza_suma_de_control(cnp);

    for (i = 1; i <= 52; i ++) {
        sprintf(cnp + 7, "%02i", i);
        val = baza;

        val += (cnp[7] - '0') * 5;
        val += (cnp[8] - '0') * 8;

        for (j = 1; j < 1000; j ++) {
            sprintf(cnp + 9, "%03i", j);

            suma = val;

            suma += (cnp[9] - '0') * 2;
            suma += (cnp[10] - '0') * 7;
            suma += (cnp[11] - '0') * 9;

            suma %= 11;
            if (suma == 10)
                suma = 1;

            sprintf(cnp + 12, "%i", suma);

            state[0] = 0;
            state[1] = 0;
            state[2] = 0;
            state[3] = 0;
            state[4] = 0;

            sha1_hash((uint8_t *)cnp, 13, state);

            if (!memcmp(state, isu, sizeof(state))) {
                fprintf(stdout, "Extracted CNP from ISU: %s\n", cnp);
                return 1;
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    static uint32_t state[STATE_LEN];
    static uint32_t isu[STATE_LEN];
    int i;
    int sex = 0, y = 0, m = 0, d = 0, days = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s ISU [prefix]\n", argv[0]);
        return -1;
    }

    int len = strlen(argv[1]);
    if (len != 40) {
        fprintf(stderr, "Invalid ISU: %s\nISU must have exactly 40 characters.\n", argv[1]);
        return -1;
    }


    if (argc > 2) {
        if (strlen(argv[2]) != 7) {
            fprintf(stderr, "Invalid prefix: %s\nprefix must be exactly 7 characters long.\n", argv[2]);
            return -1;
        }

        sex = (argv[2][0] - '0');
        y = (argv[2][1] - '0') * 10 + (argv[2][2] - '0');
        m = (argv[2][3] - '0') * 10 + (argv[2][4] - '0');
        d = (argv[2][5] - '0') * 10 + (argv[2][6] - '0');

        if (!sex) {
            fprintf(stderr, "Invalid prefix: %s\n", argv[2]);
            return -1;
        }
    }

    hexStr2Arr((unsigned char *)isu, argv[1]);
    for (i = 0; i < STATE_LEN; i ++) {
        isu[i] = REVERSE_LONG(isu[i]);
    }

    if (!sex) {
        for (sex = 1; sex < 9; sex ++) {
            for (y = 99; y >= 0; y --) {
                fprintf(stderr, "Please wait ... scanning year: %i\n", y);
                for (m = 1; m <= 12; m ++) {
                    switch (m) {
                        case 1:
                        case 3:
                        case 5:
                        case 7:
                        case 8:
                        case 10:
                        case 12:
                            days = 31;
                            break;
                        case 2:
                            days = 28;
                            if ((y % 4) == 0)
                                days = 29;
                            break;
                        default:
                            days = 30;
                            break;
                    }
                    for (d = 1; d < days; d ++) {
                        if (find_cnp(sex, y, m, d, isu)) {
                            return 0;
                        }
                    }
                }
            }
        }
        fprintf(stderr, "CNP not found - invalid ISU!\n");
    } else {
        if (!find_cnp(sex, y, m, d, isu))
            fprintf(stderr, "CNP nout found - invalid ISU!\n");
    }

    return 0;
}
