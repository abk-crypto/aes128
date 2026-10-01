#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <getopt.h>
#include <string.h>
#include <err.h>
#include <sys/random.h>

#include "aes.h"

typedef enum {
  MODE_CBC,
  MODE_CTR,
  MODE_GCM,
} BLOCK_CIPHER_MODE;

// converitr la clé et l'iv
void convert_hex_to_bytes(const char hex[], uint8_t byte[16]) {

  for(int i = 0; i < 16; i++) {
    unsigned int temp;
    sscanf(hex + 2*i, "%2x",&temp);
    byte[i] = (uint8_t)temp;
  }
}

// Générer des octet alétoire pour l'iv
void generate_iv(uint8_t iv[16]) {
  ssize_t n = getrandom(iv, 16, 0);
  if(n != 16) {
    errx(EXIT_FAILURE, "erreur lors de la geneartion de l'iv\n");
  }
}

//Faire le xor entre deux blocks
void xor(uint8_t a[16], const uint8_t b[16]) {
  for(int i = 0;i < 16; i++) {
    a[i] ^= b[i];
  }
}

// fonction pour afficher de l'aide 



bool encrypt_mode = false; 
bool key_given = false;
bool iv_given = false;
bool decrypt_mode = false;


int main(int argc, char *argv[])
{ 
  FILE *f;
  FILE *output_file;
  uint8_t key[16];
  uint8_t iv[16];
  BLOCK_CIPHER_MODE mode = MODE_CBC;
  char *output_filename = NULL;

  struct option const long_opts[] = {
    {"hlep",    no_argument,        NULL, 'h'},
    {"key",     required_argument,  NULL, 'k'},
    {"encrypt", no_argument,        NULL, 'e'},
    {"iv",      required_argument,  NULL, 'v'},
    {"mode",    required_argument,  NULL, 'm'},
    {"output",  required_argument,  NULL, 'o'},
    {"decrypt", no_argument,        NULL, 'd'},
    {NULL,      0,                  NULL,  0}
  };

  int optc;
  while((optc = getopt_long(argc,argv, "hk:ev:m:o:d",long_opts ,NULL)) != -1) {
    switch (optc)
    {
    case 'h':
      printf("Utilisation:./aes128 [options] fichier_entrée fichier_sortie\n"
             "Options:\n"
             "-k, --key      Clé AES128 en hexadécimal(32 caractéres)\n"
             "-v, --iv       IV en hexadécimal(32 caractéres)\n"
             "-e, --encrypt  Chiffrer un fichier\n"
             "-d, --decrypt  Déchiffrer le fichier\n"
             "-d, --mode     Choisir le mode de chiffrment(CBC,CTR,GCM)\n"
             "-o, --output   Donner le fichier de sortie\n"
            );
      exit(EXIT_SUCCESS);
    
    case 'k':
      key_given = true;
      if(strlen(optarg) != 32) {
        errx(EXIT_FAILURE, "La clé doit faire exactement 32 caractéres");
      }
      convert_hex_to_bytes(optarg,key);
      break;

    case 'e':
      encrypt_mode = true;
      break;

    case 'v':
      iv_given = true;
      if(strlen(optarg) != 32) {
        errx(EXIT_FAILURE, "L' iv doit faire exactement 32 caractéres");
      }
      convert_hex_to_bytes(optarg, iv);
      break;
      
      case 'm':
        if(strcmp(optarg, "cbc") == 0) {
          mode = MODE_CBC;
        }
        else if (strcmp(optarg, "ctr") == 0) {
          mode = MODE_CTR;
        }
        else if (strcmp(optarg, "gcm") == 0) {
          mode = MODE_GCM;
        }
        else {
          errx(EXIT_FAILURE, "mode %s n'est pas supporté\n",optarg);
        }

        break;

      case 'o':
        output_filename = optarg;
        break;
        
      case 'd': 
        decrypt_mode = true;
        break;

    default:
      errx(EXIT_FAILURE,"option %s invalid",argv[optind - 1]);
      break;
    }
  }

  if(optind >= argc) {
    errx(EXIT_FAILURE, "Vous devez fournir le fichier d'entrée\n");
  }
 
  if (!key_given){
    errx(EXIT_FAILURE, "vous devez fournir la clé avec -k !!\n");
  }

  if(output_filename == NULL) {
    errx(EXIT_FAILURE, "Vous devez fournir un fichier de sortie\n");
  }

  if(encrypt_mode && decrypt_mode) {
    printf("Les options -e et -d sont incompatibles\n");
  }

  // chiffrement 
  if(encrypt_mode ) {
    if (!iv_given) {
        generate_iv(iv);
    }
    // mode CBC
    if (mode == MODE_CBC) {
      f = fopen(argv[optind], "rb");
    if (f == NULL) {
      err(EXIT_FAILURE, "error lors de l'ouverture du fichier");
    }
    
    // on se point à la fin du fichier pour claculer sa taille
    if(fseek(f, 0, SEEK_END) != 0) {
      err(EXIT_FAILURE, "erreur lors du déplacment dans le fichier");
    }

    long file_size = ftell(f);
    if (file_size == -1) {
      err(EXIT_FAILURE, "error lors du ftel");
    }
    // on revient au début du fichier pour le lire aprés
    if(fseek(f, 0, SEEK_SET) != 0) {
      err(EXIT_FAILURE, "erreur lors du retour au début du fichier");
    }

    // on clacule le padding 
    size_t padding = 16 - (file_size % 16);
    uint8_t *plaintext = malloc(file_size + padding);
    if(plaintext == NULL) {
      err(EXIT_FAILURE, "Erreur lors de l'allocation mémoire");
    }

    size_t size = (size_t) file_size;
    size_t n = fread(plaintext, 1, size, f);
    if(n != size) {
      err(EXIT_FAILURE, "erreur lors de la lecture du fichier");
    }
    
  // on applique le padding ici on utlise le format PKCS#7
    for (size_t i = 0; i < padding; i++) {
      plaintext[file_size + i] = padding;  
    }
    size_t total_size = file_size + padding;

    uint8_t previous[16];
    output_file = fopen(output_filename, "wb");
    if(output_file == NULL) {
      err(EXIT_FAILURE, "Erreur lors de l'ouverture du fichier de sortie");
    }

    if(fwrite(iv,1,16,output_file) != 16) {
      err(EXIT_FAILURE,"Erreur lors de l'écriture de l'iv");
    }

    memcpy(previous,iv,16);

    for (size_t i = 0; i < total_size; i += 16) {
      state_t state;
      uint8_t block[16];
      uint8_t chipher_txt[16];

      memcpy(block,&plaintext[i],16);
      xor(block,previous);
      chipher(block,key,state,chipher_txt);
      if(fwrite(chipher_txt,1, 16,output_file) != 16) {
        err(EXIT_FAILURE, "erreur lors de l'ecriture du chiphertext");
      }

      memcpy(previous,chipher_txt,16);
    }

    free(plaintext);
    fclose(f);
    fclose(output_file);
  }

  else if(mode == MODE_CTR) {
    printf("mode pas encore implémenté\n");
  }
    }

    // déchifrement
    if(decrypt_mode) {
      f = fopen(argv[optind], "rb");
    if (f == NULL) {
      err(EXIT_FAILURE, "error lors de l'ouverture du fichier");
    }

    if(fread(iv,1,16,f) != 16) {
      errx(EXIT_FAILURE,"Erreur lors de la lecture de l'iv\n");
    }

    uint8_t previous[16];
    output_file = fopen(output_filename, "wb");
    if(output_file == NULL) {
      err(EXIT_FAILURE, "Erreur lors de l'ouverture du fichier de sortie");
    }
    
    memcpy(previous,iv,16);

    uint8_t block[16];
    uint8_t plaint_txt[16];
    uint8_t last_plaint_txt[16];  // on stocke le dernier block pour le dépadding
    bool first_block = true;

    while (fread(block,1,16,f) == 16) {
      state_t state;
      
      decrypt(block,key,state,plaint_txt);
      xor(plaint_txt,previous);
      if(!first_block) {
        if(fwrite(last_plaint_txt,1, 16,output_file) != 16) {
        err(EXIT_FAILURE, "erreur lors de l'ecriture du chiphertext");
      }
      }

      memcpy(last_plaint_txt, plaint_txt, 16);
      first_block = false;
      memcpy(previous,block,16);
    }

    if (first_block) {
    errx(EXIT_FAILURE, "Le fichier ne contient aucun bloc chiffré");
    }

    uint8_t padding = last_plaint_txt[15];
    if(padding < 1 || padding > 16) {
      errx(EXIT_FAILURE, "padding invalide");
    }

    for (int i = 0; i <  padding; i++) {
      if(last_plaint_txt[15 - i] != padding) {
        errx(EXIT_FAILURE, "Padding PKCS#7 invalide\n");
      }
    }

    size_t last_plaintxt_size = 16 - padding;
    if(fwrite(last_plaint_txt,1,last_plaintxt_size,output_file) 
      != last_plaintxt_size) {
        err(EXIT_FAILURE, "erreur lors du l'ecriture du dernier block");
    }

    fclose(f);
    fclose(output_file);
    }
  return 0;
}  