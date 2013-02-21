#include "fileCrypt.h"
#include <gcrypt.h>
#include <openssl/evp.h>
#include "error.h"

#define min(x,y) ((x) > (y)? (y) : (x))

#define BUFFER_SIZE 512

void hashPassword(char* plainText, unsigned char *hashOut, unsigned char *salt){
	//Hashes the password using PBKDF2 with SHA1
	int plainText_len = strlen(plainText);
	
	//PBKDF2 implementation from OpenSSL. Tested using some of the test vectors described in  http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06#page-3
	if(PKCS5_PBKDF2_HMAC_SHA1(plainText, plainText_len, 
							salt, PASS_SALT_SIZE, PASS_PBKDF2_ITERATIONS, 
							PASS_KEY_LENGTH, hashOut) == 0) error("Error while generating password hash");
}

void encryptedIntegrityProtectedWrite(gcry_cipher_hd_t *gchd, gcry_md_hd_t *gcmdhd, unsigned char* data, int data_len, FILE* outputFdesc){
	unsigned char inBuffer[BUFFER_SIZE];
	//size_t buffer_len=0;
	const size_t buffer_size_bytes = sizeof(inBuffer[0])*sizeof(inBuffer);
	unsigned char outBuffer[BUFFER_SIZE];
	
	while(data_len > 0){
		//Get next chunk of data
		memset(inBuffer, 0, BUFFER_SIZE);
		memcpy(inBuffer, data, min(buffer_size_bytes, sizeof(*data)*data_len));
		
		//Hash step
		gcry_md_write(*gcmdhd, inBuffer, buffer_size_bytes);
		//Cipher step
		gcrExitOnError( gcry_cipher_encrypt(*gchd, outBuffer, buffer_size_bytes,
												  inBuffer,  buffer_size_bytes));
		//writeout
		fwrite(outBuffer, sizeof(outBuffer[0]), BUFFER_SIZE, outputFdesc);
		if(ferror(outputFdesc)) error("encryptedIntegrityProtectedWrite(): Error while trying to write the output file descriptor");
		
		data_len -= BUFFER_SIZE;
	} 
}

void encryptedIntegrityProtectedRead(gcry_cipher_hd_t *gchd, gcry_md_hd_t *gcmdhd, unsigned char* data, int data_len, FILE* inputFdesc){
	unsigned char inBuffer[BUFFER_SIZE];
	//size_t buffer_len=0;
	const size_t buffer_size_bytes = sizeof(inBuffer[0])*sizeof(inBuffer);
	unsigned char outBuffer[BUFFER_SIZE];
	
	while(data_len > 0){
		//Get next chunk of data
		memset(inBuffer, 0, BUFFER_SIZE);
		int bytesRead;
		bytesRead = fread(inBuffer, sizeof(inBuffer[0]), BUFFER_SIZE, inputFdesc);
		if(bytesRead == 0 || ferror(inputFdesc)) error("decryptedIntegrityProtectedRead(): Error while trying to read the input file descriptor");
		
		//(De)cipher step
		gcrExitOnError( gcry_cipher_decrypt(*gchd, outBuffer, buffer_size_bytes,
											      inBuffer,  buffer_size_bytes));
		//Hash step
		gcry_md_write(*gcmdhd, outBuffer, buffer_size_bytes);
		
		//writeout
		memcpy(data, outBuffer, min(data_len, BUFFER_SIZE));
		
		data_len -= BUFFER_SIZE;
	}
}

