#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //for access()
#include <limits.h> //for PATH_MAX
#include <string.h> //for strncpy(), strlen(), strncat()
#include <libgen.h> //for basename()

#include "fileCrypt.h" //for encryptFile() and decryptFile()
#include "error.h"     //for error()
#include "net.h"       //for net_connect() and net_listen()

//ARGMODE_* sets a program codepath depending on the program arguments
// It has nothing to do with a cipher's mode of operation (defined in the CIPHER_* macros in filecrypt.h)
#define ARGMODE_FILEONLY 'f'
#define ARGMODE_SEND     's'
#define ARGMODE_RECV     'r'
#define ARGMODE_DECRONLY 'D'

//Buffer size for file operations
#define BUFFER_SIZE 512

#define min(x,y) ((x) > (y)? (y) : (x))

void hexprint(char* name, void* anything, size_t len){
	//Convenience debugging function to print number strings
	size_t i;
	printf("%s: ", name);
	for(i=0;i<len;i++) printf("%x ", ((unsigned char*)anything)[i]);
	printf("\n");
}

long int fileLength(FILE* fdesc){
	//Returns the length of a file open with "rb"
	//Can return -1 on failure
	long int currentPos = ftell(fdesc); //Saves current seek position
	fseek(fdesc, 0, SEEK_END);
	long int size = ftell(fdesc);
	fseek(fdesc, 0, currentPos);
	return size;
}

int isFileReadable(char* fileName){
	//Tries to open the file, then closes. If succesful, the file is readable.
	int fileOpened = 0;
	FILE* fdesc = fopen(fileName, "rb");
	fileOpened = fdesc != 0;
	if(fileOpened) fclose(fdesc);
	return fileOpened;
}

int fileExists(char* fileName){
	//Checks if a file of path fileName exists
	return access(fileName, F_OK) == 0;
}

int getArgs(int argc, char** argv, char** inputFile, char** outIp, char** inPort){
	//Ugly argument processing
	int argmode = 0;
	if(strcmp(basename(argv[0]), "fcenc") == 0){
		//fcenc mode 
		if(argc == 2){
			(*inputFile) = argv[1];
			argmode = ARGMODE_FILEONLY; //fileonly
		}
		if(argc == 3 && argv[1][0] != '-'){
			(*inputFile) = argv[1];
			(*outIp)     = argv[2];
			argmode = ARGMODE_SEND; //send
		}
	}
	
	else if(strcmp(basename(argv[0]), "fcdec") == 0){
		if(argc == 3 && argv[1][0] == '-' && strlen(argv[1]) == 2){
			if(argv[1][1] == 'd'){
				(*inPort) = argv[2];
				argmode = ARGMODE_RECV; //receive
			}
			else if(argv[1][1] == 'i'){
				(*inputFile) = argv[2];
				argmode = ARGMODE_DECRONLY; //decrypt only
			}
		}
	}
	
	else{
		error("Invalid executable program name. Please rename the executable to either \"fcenc\" or \"fcdec\".");
	}
	if(argmode == 0) error("Invalid arguments.\n Usage: fcenc <input file> [<output IP-addr:port>]\n        fcdec [-d <port>] | [-i <input file>]");
	if(argmode != ARGMODE_RECV && !isFileReadable(*inputFile)) error("Invalid/unreadable input file (does the file exist?)");
	return argmode;
} 

void initialiseGcrypt(){
	//Gcrypt init, http://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library
	//Initialise gcrypt
	if((!gcry_check_version(GCRYPT_VERSION))){
		error("libgcrypt version mismatch.");
	}
	//Intialise secure memory
	gcrExitOnError( gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0));
	
	gcrExitOnError( gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0));

}

void getPlaintextPasswordStdin(char* plainTextPassword){
	//A simple function to standardise password input
	printf("Password (max length: %d): ", PASS_PLAIN_LENGTH); //XXX echo is enabled
	fgets(plainTextPassword, PASS_PLAIN_LENGTH, stdin);
}

int fcenc(gcry_cipher_hd_t gchd, gcry_md_hd_t gcmdhd, char argmode, char* inputFileName, char* outIp){	
	//Allocing secure memory to hold the plaintext password, key and hmacKey
	char *plainTextPassword = gcry_malloc_secure(sizeof(char)*PASS_PLAIN_LENGTH);
	if(plainTextPassword == 0) error("Error while trying to alloc memory for password");
	
	unsigned char *key = gcry_malloc_secure(PASS_KEY_LENGTH*sizeof(unsigned char));
	if(key == 0) error("Error while trying to alloc secure memory for key");
	
	unsigned char *hmacKey = gcry_malloc_secure(PASS_KEY_LENGTH*sizeof(unsigned char));
	if(hmacKey == 0) error("Error while trying to alloc secure memory for key");
	
	unsigned char salt[PASS_SALT_SIZE];
	unsigned char hmacSalt[PASS_SALT_SIZE];
	unsigned char iv[CIPHER_IV_SIZE];
	
	unsigned int hmacLen = gcry_md_get_algo_dlen(gcry_md_get_algo(gcmdhd));
	
	//Although infdesc might imply other types of file descriptors (e.g. sockets)
	//infdesc SHOULD ALWAYS be a file (or, at least, a rewindable file descriptor)
	FILE* infdesc = fopen(inputFileName,"rb");
	if(infdesc == 0) error("Error while trying to open the input file");
	
	FILE* outfdesc = 0; //output file descriptor
	
	//We store the original filename, making it easier to send it encrypted over the wire.
	//Also, we are considering filenames as sensitive info. While we may not control the filename 
	//as it is in the filesystem, we can at least warn the user if the original filename was
	//changed. (e.g. "letterOfResignation.txt" instead of "justARant.txt").
	char inFilePath[PATH_MAX], inFileName[PATH_MAX];
	strncpy(inFilePath, inputFileName, PATH_MAX);
	strncpy(inFileName, basename(inFilePath), PATH_MAX);
	long int inFileSize = fileLength(infdesc);
	
	if(argmode == ARGMODE_FILEONLY){
		//The output file name is the input file name with .fc appended to it.
		char outFileName[PATH_MAX];
		strncpy(outFileName, inputFileName, PATH_MAX);
		strncat(outFileName, ".fc", PATH_MAX);
		
		if(fileExists(outFileName)){
			error("Output file already exists.");
		}
		
		outfdesc = fopen(outFileName, "wb");
	}
	else if(argmode == ARGMODE_SEND){
		//Connect to other side
		int sock = net_connect(outIp);
		if(sock == 0) error("Error while trying to connect to fcdec daemon.");
		outfdesc = fdopen(sock, "wb");
	}
	
	if(!outfdesc) error("Error while opening output file descriptor for writing");
	
	getPlaintextPasswordStdin(plainTextPassword);
	
	//We're encrypting, hence we need to generate a safe salt for the password (and hmac) and an IV
	gcry_randomize(salt,     PASS_SALT_SIZE*sizeof(char), GCRY_STRONG_RANDOM); //GCRY_VERY_STRONG_RANDOM
	gcry_randomize(iv,       CIPHER_IV_SIZE*sizeof(unsigned char), GCRY_STRONG_RANDOM);
	gcry_randomize(hmacSalt, PASS_SALT_SIZE*sizeof(char), GCRY_STRONG_RANDOM);
			
	//Create cipher and hmac key from plainTextPassword
	hashPassword(plainTextPassword, key, salt);
	hashPassword(plainTextPassword, hmacKey, hmacSalt);
	
	//Populate the cript context handle with salt and iv
	gcrExitOnError( gcry_cipher_setkey(gchd, (void*)key, PASS_KEY_LENGTH*sizeof(unsigned char)));
	gcrExitOnError( gcry_cipher_setiv( gchd, (void*)iv,  CIPHER_IV_SIZE*sizeof(unsigned char)));
	
	//Populate the message digest context handle with hmac key
	gcrExitOnError( gcry_md_setkey(gcmdhd, hmacKey, PASS_KEY_LENGTH));
	
	unsigned char inBuffer[BUFFER_SIZE];

//File Header
	//Write crypto salt, hmacSalt and iv in the clear
	fwrite(salt,     sizeof(unsigned char),PASS_SALT_SIZE,  outfdesc);
	if(ferror(outfdesc)) error("ferror while writing salt.");
	fwrite(iv,       sizeof(unsigned char),CIPHER_IV_SIZE,  outfdesc);\
	if(ferror(outfdesc)) error("ferror while writing IV.");
	fwrite(hmacSalt, sizeof(unsigned char),PASS_SALT_SIZE,  outfdesc);
	if(ferror(outfdesc)) error("ferror while writing hmacSalt.");
	
	encryptedIntegrityProtectedWrite(&gchd, &gcmdhd, (unsigned char*) inFileName,  sizeof(inFileName[0])*sizeof(inFileName), outfdesc);
	encryptedIntegrityProtectedWrite(&gchd, &gcmdhd, (unsigned char*) &inFileSize, sizeof(inFileSize),      outfdesc);

//File body (encrypted plaintext file)
	while(!feof(infdesc)){
		int bytes_read;
		bytes_read = fread(inBuffer, sizeof(inBuffer[0]), BUFFER_SIZE, infdesc);
		if(ferror(infdesc)) error("ferror while reading encrypted file.");
		
		//Encryption operation//
		encryptedIntegrityProtectedWrite(&gchd, &gcmdhd, inBuffer, bytes_read, outfdesc);
	}
	
//File Footer
	//HMAC
	unsigned char* hmac = gcry_md_read(gcmdhd, 0);
	if(hmac == 0) error("Error while retrieving hmac");
	
	fwrite(hmac, sizeof(hmac[0]), hmacLen, outfdesc);
	if(ferror(outfdesc)) error("ferror while trying to write file's HMAC.");
			
//Cleanup
	gcry_free(plainTextPassword);
	gcry_cipher_reset(gchd);
	gcry_md_reset(gcmdhd);
	
	fclose(infdesc);
	fclose(outfdesc);
	return 0;
}

int fcdec(gcry_cipher_hd_t gchd, gcry_md_hd_t gcmdhd, char argmode, char* inputFileName, char* inPort){
	//Allocing secure memory to hold the plaintext password, key and hmacKey
	char *plainTextPassword = gcry_malloc_secure(sizeof(char)*PASS_PLAIN_LENGTH);
	if(plainTextPassword == 0) error("Error while trying to alloc memory for password");
	
	unsigned char *key = gcry_malloc_secure(PASS_KEY_LENGTH*sizeof(unsigned char));
	if(key == 0) error("Error while trying to alloc secure memory for key");
	
	unsigned char *hmacKey = gcry_malloc_secure(PASS_KEY_LENGTH*sizeof(unsigned char));
	if(hmacKey == 0) error("Error while trying to alloc secure memory for key");
	
	unsigned char salt[PASS_SALT_SIZE];
	unsigned char hmacSalt[PASS_SALT_SIZE];
	unsigned char iv[CIPHER_IV_SIZE];
	
	unsigned int hmacLen = gcry_md_get_algo_dlen(gcry_md_get_algo(gcmdhd));
	
	FILE* infdesc = 0;
	FILE* outfdesc = 0; //output file descriptor
	
	char outFileName[PATH_MAX];
	char outFileNameDecrd[PATH_MAX];
	int outFileSize =0;
	
	if(argmode == ARGMODE_DECRONLY){
		//Reading directly from a file
		infdesc = fopen(inputFileName,"rb");
		if(infdesc == 0) error("Error while trying to open the input file");
		
		strncpy(outFileName, inputFileName, PATH_MAX);
		
		//In this mode, the output file name can be inferred directly from
		//the input file name.
		int inputFileName_len = strlen(inputFileName);
		if(strncmp(&outFileName[inputFileName_len-5], ".fc", 5) != 0){
			error("Input encrypted file must have a \".fc\" extension.");
		}
		outFileName[inputFileName_len-5] = 0;
	}
	else if(argmode == ARGMODE_RECV){
		//Receiving a file from a network stream
		char listenaddr[256] = "0.0.0.0:";
		strncat(listenaddr, inPort, 256);
		int sock = net_listen(listenaddr);
		if(sock == 0) error("Error while creating listening socket.");
		infdesc = fdopen(sock, "r");
		//Since we can't determine the filename at this point, we set outFileName to be an empty string.
		outFileName[0]=0;
	}
	
//File Header
	//Read crypto salt, hmacSalt and iv in the clear
	fread(salt,     sizeof(unsigned char),PASS_SALT_SIZE,  infdesc);
	if(ferror(infdesc)) error("ferror while retrieving passkey salt.");
	fread(iv,       sizeof(unsigned char),CIPHER_IV_SIZE,  infdesc);
	if(ferror(infdesc)) error("ferror while retrieving IV.");
	fread(hmacSalt, sizeof(unsigned char),PASS_SALT_SIZE,  infdesc);
	if(ferror(infdesc)) error("ferror while retrieving hmacSalt.");
	
	getPlaintextPasswordStdin(plainTextPassword);

	hashPassword(plainTextPassword, key, salt);
	
	//Populate the cript context handle with salt and iv
	gcrExitOnError( gcry_cipher_setkey(gchd, (void*)key, PASS_KEY_LENGTH*sizeof(unsigned char)));
	gcrExitOnError( gcry_cipher_setiv( gchd, (void*)iv,  CIPHER_IV_SIZE*sizeof(unsigned char)));
	
	//Populate the message digest context handle with hmac key
	hashPassword(plainTextPassword, hmacKey, hmacSalt);
	gcrExitOnError( gcry_md_setkey(gcmdhd, hmacKey, PASS_KEY_LENGTH));
	
	encryptedIntegrityProtectedRead(&gchd, &gcmdhd, (unsigned char*) outFileNameDecrd, sizeof(outFileNameDecrd[0])*sizeof(outFileNameDecrd), infdesc);
	encryptedIntegrityProtectedRead(&gchd, &gcmdhd, (unsigned char*) &outFileSize,     sizeof(outFileSize),                                  infdesc);
	
	if(outFileName[0] == 0){
		memcpy(outFileName, outFileNameDecrd, sizeof(outFileName[0])*sizeof(outFileName));
	}
	
	if(memcmp(outFileName, outFileNameDecrd, min(strlen(outFileName),sizeof(outFileName[0])*sizeof(outFileName))) != 0){
		printf("WARNING: Supposed original filename (\"%s\") doesn't match external filename (\"%s\"). This may be due to a corrupted file or a wrong password\n", outFileNameDecrd, outFileName);
	}
	
	if(fileExists(outFileNameDecrd)){
			error("Output file already exists.");
	}
	outfdesc = fopen(outFileNameDecrd, "wb");
	if(!outfdesc) error("Error while opening output file descriptor for writing");
	
	
//File body (encrypted plaintext file)
	long int fileLen = outFileSize;
	if(fileLen <=0) error("Invalid filelength. The password used may be wrong or file may be corrupted.");
	while(fileLen > 0){
		unsigned char outBuffer[BUFFER_SIZE];
		int buffer_len = min(fileLen*sizeof(unsigned char), sizeof(outBuffer[0])*sizeof(outBuffer));
		
		//Decryption operation//
		encryptedIntegrityProtectedRead(&gchd, &gcmdhd, outBuffer, sizeof(outBuffer[0])*sizeof(outBuffer), infdesc);
		
		fwrite(outBuffer, sizeof(outBuffer[0]), buffer_len, outfdesc);
		if(ferror(outfdesc)) error("Error while writing output decrypted file");
		fileLen -= BUFFER_SIZE;
	}

//File footer (HMAC)
	unsigned char* hmac;
	hmac =  gcry_md_read(gcmdhd, 0);
	if(hmac == 0) error("Error while retrieving hmac");
	
	unsigned char hmacRef[HMAC_MAX_SIZE];
	fread(hmacRef, sizeof(hmacRef[0]), hmacLen, infdesc);
	if(ferror(outfdesc)) error("Error while reading file's HMAC");
	
	if(memcmp(hmacRef, hmac, hmacLen) != 0){
		printf("ERROR: HMAC doesn't match original file's. Either the passwords don't match, or the file is corrupted.\n");
		hexprint(" hmac (original)", hmacRef, hmacLen);
		hexprint(" hmac (computed)", hmac, hmacLen);
		return 1;
	}

//Cleanup
gcry_free(plainTextPassword);
	gcry_cipher_reset(gchd);
	gcry_md_reset(gcmdhd);
	
	fclose(infdesc);
	fclose(outfdesc);
	return 0;
}

int main(int argc, char** argv){
	//http://www.gnupg.org/documentation/manuals/gcrypt/Working-with-cipher-handles.html#Working-with-cipher-handles
	int mainret = 0;
	
	struct addrinfo *res = parseValidateAddress("192.168.1.1:8080");
	freeaddrinfo(res);
	
	//Argument processing
	char *inputFileName, *outIp, *inPort;
	int argmode = getArgs(argc, argv, &inputFileName, &outIp, &inPort);
		
	//Initialise gcrypt. Will exit(1) on error.
	initialiseGcrypt();

	//Create Grypt cipher and hashing context handle, setting the algorithm and cipher mode to be used
	//by all hashing and encryption instructions in this program
	gcry_cipher_hd_t gchd; 	 //cipher context handle
	gcry_md_hd_t     gcmdhd; //message digest context handle
	gcrExitOnError( gcry_cipher_open(&gchd, CIPHER_ALGO, CIPHER_MODE, 0)); //XXX consider GCRY_CIPHER_SECURE flag
	gcrExitOnError( gcry_md_open(&gcmdhd, HASH_ALGO, GCRY_MD_FLAG_HMAC));
	
	//HMAC Sanity checks
	unsigned int hmacLen = gcry_md_get_algo_dlen(gcry_md_get_algo(gcmdhd));
	if(hmacLen > HMAC_MAX_SIZE) error("HMAC is too big.");
	
	
	if(argmode == ARGMODE_FILEONLY || argmode == ARGMODE_SEND){
		//In these modes, we are getting and input file and either...
		// -...writing the encrypted file into a new FILE  (ARGMODE_FILEONLY)
		// -...SENDing the encrypted file over the network (ARGMODE_SEND)
		mainret = fcenc(gchd, gcmdhd, argmode, inputFileName, outIp);
	}

//DECRYPTION
	else if(argmode == ARGMODE_DECRONLY || argmode == ARGMODE_RECV){
		//In these modes, we are reading (ARGMODE_DECRONLY) or receiving (ARGMODE_RECV)
		//an encrypted file and writing the plaintext in a local file.
		mainret = fcdec(gchd, gcmdhd, argmode, inputFileName, inPort);
	}
	
	gcry_cipher_close(gchd);
	gcry_md_close(gcmdhd);
	return mainret;
}
