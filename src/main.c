#include <stdio.h>
#include "aes.h"



int main(void)
{
  uint8_t message[16] = {
    0x12, 0x34, 0x56, 0x78,
    0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78,
    0x90, 0x21, 0x23, 0x45
  };

  state_t state;

  States(message, state);

  print_state(state);
  Subbytes(state);
  print_state(state);
  ShiftRows(state);
  print_state(state);

  return 0;
}