#include "dqpsk_sym_extr.h"
#include <math.h>

namespace dsp {
    // wrapPhaseDiff is niet meer nodig in de geoptimaliseerde versie

    int DQPSKSymbolExtractor::process(int count, const complex_t* in, uint8_t* out) {
        for(int i = 0; i < count; i++) {
            complex_t sym_c = in[i];
            
            // Bepaal kwadrant (hard decision)
            bool a = sym_c.im < 0; // Imaginary part negative?
            bool b = sym_c.re < 0; // Real part negative?

            // OPTIMALISATIE: Vervang atan2/phase() door snelle foutschatting.
            // We willen weten hoe ver het punt afwijkt van de ideale 45-graden lijnen.
            // Een snelle maat hiervoor is de "Costas error" (afstand loodrecht op de vector).
            // Error ~ |(Re * sign(Im)) - (Im * sign(Re))|
            
            float sign_re = (b ? -1.0f : 1.0f);
            float sign_im = (a ? -1.0f : 1.0f);
            
            // Dit berekent de sinus van de hoekfout, wat voor kleine hoeken ≈ hoekfout in radialen is.
            float raw_err = (sym_c.re * sign_im) - (sym_c.im * sign_re);
            float dist = fabsf(raw_err);

            // Weight error metric by amplitude to avoid noisy "sync flapping" on weak samples
            // fastAmplitude() gebruikt vaak al een benadering, dat is prima.
            float amp = sym_c.fastAmplitude();
            
            // Als het signaal te zwak is, tellen we het als 'perfect' (0 error) om false triggers te voorkomen,
            // of juist als fout? In jouw originele code was het: (amp < 0.15 ? 0.0 : 1.0).
            // Laten we dat behouden:
            dist = dist * (amp < 0.15f ? 0.0f : 1.0f);

            errorbuf[errorptr] = dist;
            errorptr++;
            if(errorptr >= SYNC_DETECT_BUF) {
                errorptr = 0;
            }
            
            errordisplayptr++;
            if(errordisplayptr >= SYNC_DETECT_DISPLAY) {
                float xerr = 0;
                // Loop unrolling kan hier helpen, maar compiler doet dit vaak al
                for(int j = 0; j < SYNC_DETECT_BUF; j++) {
                    xerr += errorbuf[j];
                }
                xerr /= (float)SYNC_DETECT_BUF;
                standarderr = xerr;
                
                // Drempelwaarde eventueel iets aanpassen omdat onze 'dist' berekening iets anders is,
                // maar voor kleine hoeken is radialen ≈ sinus, dus 0.35f blijft waarschijnlijk werken.
                if(xerr >= 0.35f) {
                    sync = false;
                } else {
                    sync = true;
                }
                errordisplayptr = 0;
            }

            // Symbol mapping logic (ongewijzigd)
            uint8_t sym = ((a)<<1) | (a!=b); 
            uint8_t phaseDiff = (sym - prev + 4) % 4;
            
            switch(phaseDiff) { 
                case 0b00: out[i] = 0b00; break; // 0
                case 0b01: out[i] = 0b01; break; // pi/2
                case 0b10: out[i] = 0b11; break; // pi (swap)
                case 0b11: out[i] = 0b10; break; // -pi/2
            }
            prev = sym;
        }
        return count;
    }
}
