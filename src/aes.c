#include <stdio.h>


#include  "aes.h"

// le sbox pris dans le document officiel du NIST(FIPS197)
const uint8_t sbox[256] = {
   //       0      1     2     3    4     5      6     7    8      9     a     b     c     d    e     f
  /*0*/    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  /*1*/    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  /*2*/    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  /*3*/    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  /*4*/    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  /*5*/    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  /*6*/    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  /*7*/    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  /*8*/    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  /*9*/    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  /*a*/    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  /*b*/    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  /*c*/    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  /*d*/    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  /*e*/    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  /*f*/    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Dans AES, le bloc de 16 octets à chiffrer est placé dans une matrice 4×4 appelée State
void States(const uint8_t in[16], state_t state) {
    for (int r = 0 ; r < NB; r++) {
        for (int c= 0; c <NB; c++) {
            state[r][c]= in[r+ 4*c];
        }
    }
}


void print_state (state_t state) {
    for (int r= 0; r < NB; r++) {
        for (int c = 0; c < NB; c++) {
            printf("%02x ",state[r][c]);
        }
        printf("\n");
    }
    printf("\n");
}

void Subbytes(state_t state) {
    for(int r = 0; r < NB; r++) {
        for (int c =0; c < NB; c++)
        state[r][c] = sbox[state[r][c]];
    }
}

void ShiftRows(state_t state) {

    /* dans le premiere ligne il n'y a pas de déclage*/

    uint8_t tmp;

    /* dans la deuxiéme ligne on fait une déclage à gauche*/
    tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    /* dans la troisiéme ligne on fait deux déclage à gauche*/
    tmp = state[2][0];
    state [2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    /* dans la quatriéme ligne on fait trois déclage à gauche*/
    tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

/*fonction pour la multiplication dans GF(8)*/

static uint8_t Xtime (uint8_t x) {
    return ((x >> 7) & 1) ? 
            (x << 1) ^ 0x1b : (x << 1) ;
}

/* la fonction mixcolumn : On multiplie  chaque colonne du state
   par une matrice donné dans le  FIPS197*/

void MixColumn(state_t state) {
     uint8_t col[NB]; // pour stockerchaque colonne du state
     for(int c = 0; c < NB; c++) {
        for(int r = 0; r < NB;r++) {
            col[r] = state[r][c];
        }
        state[0][c] = Xtime(col[0]) ^ (col[1] ^ (Xtime(col[1]))) ^ col[2] ^ col[3];
        state[1][c] = col[0] ^ Xtime(col[1]) ^ (col[2] ^ Xtime(col[2])) ^ col[3];
        state[2][c] = col[0] ^ col [1] ^ Xtime(col[2]) ^ (Xtime(col[3]) ^ col [3]);
        state[3][c] = (Xtime(col[0]) ^ col[0]) ^ col[1] ^ col [2] ^ Xtime(col[3]);
     }
}

static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36
};

void KeyExpansion(uint8_t key[16], uint8_t w[NW][4]){
    uint8_t tmp[4];

    for (int i = 0; i < NK; i++) {
        w[i][0] = key[4*i];
        w[i][1] = key[4*i+1];
        w[i][2] = key[4*i+2];
        w[i][3] = key[4*i+3];
    }
 // afficher les clé de tour pour le debug
 
    for(int i = NK; i < NW; i++) {
        tmp[0] = w[i-1][0];
        tmp[1] = w[i-1][1];
        tmp[2] = w[i-1][2];
        tmp[3] = w[i-1][3];

        if (i % NK == 0) {

            // on applique rotward 
            uint8_t temp = tmp[0];
            tmp[0] = tmp[1];
            tmp[1] = tmp[2];
            tmp[2] = tmp[3];
            tmp[3] = temp;

            // on applique sbox
            tmp[0] = sbox[tmp[0]];
            tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]];
            tmp[3] = sbox[tmp[3]];

            tmp[0] ^= Rcon[i / NK];

        }
        else if (NK > 6 && i % NK == 4) {
            tmp[0] = sbox[tmp[0]];
            tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]];
            tmp[3] = sbox[tmp[3]];
        }

        w[i][0] = w[i - NK][0] ^ tmp [0];
        w[i][1] = w[i - NK][1] ^ tmp [1];
        w[i][2] = w[i - NK][2] ^ tmp [2];
        w[i][3] = w[i - NK][3] ^ tmp [3];

    }
}

void AddRoundKey(state_t state, uint8_t w[NW][4],int round){
    for (int c= 0; c < NB; c++) {
        for (int r = 0; r < NB; r++) {
            state [r][c] ^= w[4*round + c][r];
        }
    }
}

void chipher(uint8_t in[16], uint8_t key[16], state_t state, uint8_t chiper_txt[16]) {
    
    uint8_t w[NW][4];
    
    // le bloc de 16 octes est mis dans le state
    States(in, state);

    // expansion de la clé
    KeyExpansion(key,w);

    // on extrait les 4 premiers mots de w : la clé du round 0
    AddRoundKey(state,w,0);

    // on passe au tour suivant
    for (int round = 1 ; round < NR; round++) {
        Subbytes(state);
        ShiftRows(state);
        MixColumn(state);

        // on extrait les clés pour chaque tour 
        AddRoundKey(state,w,round);
    }
    // le dernier tour : on fait pas de mixcolumn
    Subbytes(state);
    ShiftRows(state);
    
    // on extrait la clé du derneir tout
    
    AddRoundKey(state,w,NR);

    for (int c = 0; c < NB; c++) {
        for (int r = 0; r < NB; r++) {
            chiper_txt[r + 4*c] = state[r][c];
        }
    }
}

//Sbox inverse pour le déchiffrement
const uint8_t invsbox[256] = {
   //       0      1     2     3     4     5     6     7     8     9     a     b     c     d     e    f
 /*0*/     0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
 /*1*/     0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
 /*2*/     0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
 /*3*/     0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
 /*4*/     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
 /*5*/     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
 /*6*/     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
 /*7*/     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
 /*8*/     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
 /*9*/     0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
 /*a*/     0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
 /*b*/     0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
 /*c*/     0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
 /*d*/     0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
 /*e*/     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
 /*f*/     0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

void invSubytes(state_t state) {
    for (int c =0; c < NB; c++) {
        for(int r = 0; r <NB; r++) {
            state[r][c] = invsbox[state[r][c]];
        }
    }
}

void invShiftRows(state_t state) {
    uint8_t tmp;

    // ligne 1: Déclage de 1 vers la droite
    tmp =  state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;

    // ligne 2 : Déclage de 2 vers la doite
    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    // ligne 3: Déclage de 3 vers la droite
    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

// multiplication dans GF(2^8)
uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t tmp = a;
    
    // on boucle sur tous les bit de b
    while (b != 0) {
        // on recupére le bit de poid faible
        if (b & 1) {
            result ^= tmp;
        }
        // on double tmp
        tmp = Xtime(tmp);
        // on deale b à droite pour traiter le bit suivant
        b >>= 1; 

    }
    return result;
}

void invMixColumn(state_t state) {
    // on stock chaque colone dans un tableau
    uint8_t col[4];
    for(int c = 0; c < NB; c++) {
        for (int r = 0; r < NB; r++) {
            col[r] = state[r][c];
        }
        // on fait la multiplication avec la matrice
        state[0][c] = multiply(col[0],0x0e) ^ multiply(col[1],0x0b) ^ multiply(col[2],0x0d) ^ multiply(col[3],0x09);
        state[1][c] = multiply(col[0],0x09) ^ multiply(col[1],0x0e) ^ multiply(col[2],0x0b) ^ multiply(col[3],0x0d);
        state[2][c] = multiply(col[0],0x0d) ^ multiply(col[1],0x09) ^ multiply(col[2],0x0e) ^ multiply(col[3],0x0b);
        state[3][c] = multiply(col[0],0x0b) ^ multiply(col[1],0x0d) ^ multiply(col[2],0x09) ^ multiply(col[3],0x0e);
    }
}

//fonction pour le dechiffremnt
void decrypt(uint8_t in[16], uint8_t key[16], state_t state, uint8_t plaint_txt[16]) {
    //tableau qui contient les mots de expansion key
    uint8_t w[NW][4];
    //le bloc de 16 octest à déchiffrer est mis dans le state
    States(in, state);
    // on fait l'expansion des clés(les memes clé pour le chiffrement)
    KeyExpansion(key, w);

    AddRoundKey(state, w, NR);
    for (int round = NR - 1 ; round >= 1; round--) {
        invShiftRows(state);
        invSubytes(state);
        AddRoundKey(state, w, round);
        invMixColumn(state);
    }

    invShiftRows(state);
    invSubytes(state);
    AddRoundKey(state, w, 0);

    for(int c = 0; c < NB; c++) {
        for (int r = 0; r < NB; r++) {
            plaint_txt[r + 4*c] = state[r][c];
        }
    }
}
