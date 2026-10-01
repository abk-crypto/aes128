# AES-128 en C

Implémentation d'un chiffrement **AES-128 en langage C**, réalisée dans un objectif d'apprentissage de la cryptographie appliquée et de la programmation bas niveau.

Le projet implémente actuellement le chiffrement et le déchiffrement **AES-128 en mode CBC**, avec gestion du **padding PKCS#7**.

## Fonctionnalités

* AES-128
* Chiffrement et déchiffrement
* Mode **CBC (Cipher Block Chaining)**
* Padding **PKCS#7**
* Génération automatique d'un IV aléatoire (si l'utilisateur ne l'a pas fournit)
* Clé AES-128 fournie en hexadécimal par l'utilisateur
* Lecture et écriture de fichiers binaires
* Interface en ligne de commande
* Options `--help`
* Vérification du padding lors du déchiffrement

## Structure du projet

```text
aes128/
├── include/
│   └── aes.h
├── src/
│   ├── aes.c
│   └── main.c
├── Makefile
└── README.md
```

## Compilation

Le projet utilise `gcc` et un Makefile.

```bash
make
```

Pour supprimer les fichiers générés :

```bash
make clean
```

## Utilisation

Afficher l'aide :

```bash
./aes128 --help
```

ou :

```bash
./aes128 -h
```

### Chiffrement

Exemple avec une clé AES-128 :

```bash
./aes128 \
  -k 00112233445566778899aabbccddeeff \
  -e \
  -m cbc \
  -o message.enc \
  message.txt
```

Si aucun IV n'est fourni, le programme en génère automatiquement un.

Il est également possible de fournir un IV :

```bash
./aes128 \
  -k 00112233445566778899aabbccddeeff \
  -e \
  -m cbc \
  -v 000102030405060708090a0b0c0d0e0f \
  -o message.enc \
  message.txt
```

### Déchiffrement

```bash
./aes128 \
  -k 00112233445566778899aabbccddeeff \
  -d \
  -m cbc \
  -o message.dec \
  message.enc
```

Lors du chiffrement CBC, l'IV est stocké au début du fichier chiffré :

```text
┌──────────────┬──────────────┬──────────────┐
│      IV      │      C1      │      C2      │ ...
│   16 octets  │   16 octets  │   16 octets  │
└──────────────┴──────────────┴──────────────┘
```

Le programme récupère donc automatiquement l'IV lors du déchiffrement.

## AES-128

AES fonctionne sur des blocs de **128 bits (16 octets)**.

AES-128 utilise une clé de **128 bits (16 octets)** et effectue **10 tours de transformation**.

L'implémentation contient notamment :

* `SubBytes`
* `ShiftRows`
* `MixColumns`
* `AddRoundKey`
* `KeyExpansion`
* les transformations inverses nécessaires au déchiffrement

## Mode CBC

Pour le chiffrement CBC, chaque bloc de plaintext est combiné par XOR avec le bloc de ciphertext précédent avant d'être chiffré.

Pour le premier bloc, l'IV est utilisé :

```text
C1 = AES(P1 XOR IV)

C2 = AES(P2 XOR C1)

C3 = AES(P3 XOR C2)
```

Lors du déchiffrement :

```text
P1 = AES⁻¹(C1) XOR IV

P2 = AES⁻¹(C2) XOR C1

P3 = AES⁻¹(C3) XOR C2
```

## Padding PKCS#7

AES travaille avec des blocs de 16 octets. Lorsque la taille du fichier n'est pas un multiple de 16, un padding PKCS#7 est ajouté.

Par exemple, s'il manque 5 octets pour compléter un bloc :

```text
05 05 05 05 05
```

Si le plaintext fait déjà exactement 16 octets, un bloc complet de padding est ajouté :

```text
10 10 10 10 10 10 10 10
10 10 10 10 10 10 10 10
```

Lors du déchiffrement, le programme vérifie la validité du padding puis le supprime avant d'écrire le plaintext final.

## Vérification

L'implémentation AES-128 a été vérifiée avec des vecteurs de test de référence et comparée aux résultats obtenus avec OpenSSL pour le mode CBC.

Exemple :

```bash
cmp message.txt message.dec
```

Si aucune sortie n'est affichée, les deux fichiers sont identiques.

## Limites actuelles

Le projet est actuellement centré sur :

* AES-128
* mode CBC
* padding PKCS#7

Les modes CTR et GCM sont prévus pour des développements futurs.

Ce projet est principalement réalisé à des fins **pédagogiques et de compréhension de l'implémentation d'AES en C**. Il ne doit pas être considéré comme une bibliothèque cryptographique destinée à la production.

## Dépendances

* GCC
* GNU Make
* Bibliothèque standard C
* Linux pour la génération d'IV avec `getrandom()`

## Objectifs d'apprentissage

Ce projet permet notamment de travailler sur :

* l'implémentation d'un algorithme cryptographique ;
* la manipulation de données binaires en C ;
* les opérations bit à bit et les calculs dans `GF(2^8)` ;
* la gestion de fichiers ;
* l'allocation mémoire ;
* les arguments de ligne de commande ;
* les modes opératoires de chiffrement ;
* le padding PKCS#7 ;
* la validation d'une implémentation cryptographique à l'aide de vecteurs de test et d'OpenSSL.
