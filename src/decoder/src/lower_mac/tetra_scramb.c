/* TETRA scrambling according to Section 8.2.5 of EN 300 392-2 V3.2.1 */
#include <stdint.h>
#include <lower_mac/tetra_scramb.h>

/* Tap macro for the standard XOR / Fibonacci form */
#define ST(x, y)	((x) >> (32-y))

/* OPTIMALISATIE: static inline zodat deze functie verdwijnt in de assembly code */
static inline uint8_t next_lfsr_bit(uint32_t *lf)
{
	uint32_t lfsr = *lf;
	uint32_t bit;

	/* taps: 32 26 23 22 16 12 11 10 8 7 5 4 2 1 */
    // Dit is een zware XOR keten. 
	bit = (ST(lfsr, 32) ^ ST(lfsr, 26) ^ ST(lfsr, 23) ^ ST(lfsr, 22) ^
	       ST(lfsr, 16) ^ ST(lfsr, 12) ^ ST(lfsr, 11) ^ ST(lfsr, 10) ^
	       ST(lfsr, 8) ^ ST(lfsr,  7) ^ ST(lfsr,  5) ^ ST(lfsr,  4) ^
	       ST(lfsr, 2) ^ ST(lfsr,  1)) & 1;
           
	lfsr = (lfsr >> 1) | (bit << 31);

	*lf = lfsr;
	return bit & 0xff;
}

int tetra_scramb_get_bits(uint32_t lfsr_init, uint8_t *out, int len)
{
	int i;
	for (i = 0; i < len; i++)
		out[i] = next_lfsr_bit(&lfsr_init);
	return 0;
}

/* XOR the bitstring at 'out/len' using the TETRA scrambling LFSR */
int tetra_scramb_bits(uint32_t lfsr_init, uint8_t *out, int len)
{
	int i = 0;

    // OPTIMALISATIE: Loop unrolling.
    // We verwerken 4 bits "tegelijk" (achter elkaar zonder loop overhead).
    // Dit helpt moderne CPU's met pipelining.
    while (i <= len - 4) {
        out[i]   ^= next_lfsr_bit(&lfsr_init);
        out[i+1] ^= next_lfsr_bit(&lfsr_init);
        out[i+2] ^= next_lfsr_bit(&lfsr_init);
        out[i+3] ^= next_lfsr_bit(&lfsr_init);
        i += 4;
    }

    // Verwerk de resterende bits (0 tot 3 stuks)
	for (; i < len; i++)
		out[i] ^= next_lfsr_bit(&lfsr_init);

	return 0;
}

uint32_t tetra_scramb_get_init(uint16_t mcc, uint16_t mnc, uint8_t colour)
{
	uint32_t scramb_init;

	mcc &= 0x3ff;
	mnc &= 0x3fff;
	colour &= 0x3f;

	scramb_init = colour | (mnc << 6) | (mcc << 20);
	scramb_init = (scramb_init << 2) | SCRAMB_INIT;

	return scramb_init;
}
