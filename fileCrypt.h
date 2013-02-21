#ifndef FILECRYPT_H
#define FILECRYPT_H
#include <gcrypt.h>
#include <stdio.h>

#define GCRYPT_VERSION "1.5.0" 

#define CIPHER_IV_SIZE 16

//Cipher algorithm and mode of operation
#define CIPHER_ALGO GCRY_CIPHER_AES256
#define CIPHER_MODE GCRY_CIPHER_MODE_CBC
#define HASH_ALGO   GCRY_MD_SHA256

//Using NIST recommendations: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
#define PASS_SALT_SIZE 32 //The length of the randomly-generated portion of the salt _shall_ be at least 128 bits (16 octets).  
#define PASS_KEY_LENGTH 32 //The kLen value _shall_ be at least 112 bits (14 octets) in length.  (Page 6)
#define PASS_PBKDF2_ITERATIONS 10000 //A minimum iteration count of 1,000  is recommended.
#define PASS_PLAIN_LENGTH 512 //Maximum length for the plaintext password

#define HMAC_MAX_SIZE 64

void hashPassword(char* plainText, unsigned char *hashOut, unsigned char *salt);

void encryptedIntegrityProtectedWrite(gcry_cipher_hd_t *gchd, gcry_md_hd_t *gcmdhd, unsigned char* data, int data_len, FILE* outputFdesc);
void encryptedIntegrityProtectedRead(gcry_cipher_hd_t *gchd, gcry_md_hd_t *gcmdhd, unsigned char* data, int data_len, FILE* inputFdesc);

#endif
