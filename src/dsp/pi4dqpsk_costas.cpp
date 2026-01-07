#include "pi4dqpsk_costas.h"
#include <math.h>

namespace dsp {
    namespace loop {
        int PI4DQPSK_COSTAS::process(int count, complex_t* in, complex_t* out) {
            for (int i = 0; i < count; i++) {
                // OPTIMALISATIE:
                // Oude methode: Eerst roteren voor loop correctie, dan roteren voor pi/4 shift.
                // Nieuwe methode: Hoeken optellen en slechts 1x sin/cos (phasor) berekenen.
                
                // 1. Update de vaste Pi/4 rotatie
                ph2 -= FL_M_PI/4.0f;
                
                // Wrap ph2 tussen -2PI en 2PI (of -PI en PI, maar phasor handelt 2PI ook prima af)
                if(ph2 <= -2.0f*FL_M_PI) {
                    ph2 += 2.0f*FL_M_PI;
                } else if (ph2 >= 2.0f*FL_M_PI) {
                    ph2 -= 2.0f*FL_M_PI;
                }

                // 2. Bereken de totale hoek: (-pcl.phase) + ph2
                float total_phase = -pcl.phase + ph2;

                // 3. Voer één complexe rotatie uit
                complex_t x = in[i] * math::phasor(total_phase);

                // 4. Update de loop (PLL)
                pcl.advance(errorFunction(x));
                
                out[i] = x;
            }
            return count;
        }

        float PI4DQPSK_COSTAS::errorFunction(complex_t val) {
            // Default QPSK error function: (sgn(I)*Q) - (sgn(Q)*I)
            // Dit is een snelle benadering van de fasefout
            float err = (math::step(val.re) * val.im) - (math::step(val.im) * val.re);
            
            // Weight loop error by amplitude to reduce jitter at low SNR
            // Dit kan nog sneller: als amplitude erg laag is, boeit de exacte wortel niet.
            // Maar voor nu behouden we de logica voor nauwkeurigheid.
            float a = sqrtf(val.re*val.re + val.im*val.im);
            if (a < 1.0f) { err *= a; }
            
            // Soft limiter
            err = err / (1.0f + fabsf(err));
            return err;
        }
    }
}
