#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <gcrypt.h>

static void error(char* msg){
	//Exits on a program error.
	printf("ERROR: %s\n", msg);
	exit(1);
}

static void gcrExitOnError(gcry_error_t err){
	//Exits on a gcrypt error, displaying the correspondent error strings.
	if(err){fprintf(stderr, "ERROR (gcrypt): %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
			exit(1);
	}
}

#endif
