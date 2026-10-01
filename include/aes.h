#ifndef AES_H
#define AES_H

#include <stdint.h>


// le nombre de ligne et colonne dans le state est 4
#define NB 4
#define NR 10
#define NK 4
#define NW 44
/**/
typedef uint8_t state_t[NB][NB];

void States(const uint8_t in[16], state_t state);

void print_state (state_t state);

void Subbytes(state_t state);

void ShiftRows(state_t state);

void MixColumn(state_t state);

void KeyExpansion(uint8_t key[16], uint8_t w[44][4]);

void chipher(uint8_t in[16], uint8_t key[16],
                 state_t state, uint8_t chiper_txt[16]);

void decrypt(uint8_t in[16], uint8_t key[16], 
                state_t state, uint8_t plaint_txt[16]);                 
#endif /* AES_H */