#ifndef AES_H
#define AES_H

#include <stdint.h>


// le nombre de ligne et colonne dans le state est 4
#define NB 4
/**/
typedef uint8_t state_t[NB][NB];

void States(const uint8_t in[16], state_t state);

void print_state (state_t state);

void Subbytes(state_t state);

void ShiftRows(state_t state);

void MixColumn(state_t state);
#endif /* AES_H */