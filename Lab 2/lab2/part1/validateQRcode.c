#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#include "time.h"

// Function to convert a char to int
int to_int(char info) {
	if (info >= 48 && info <= 57) {
		return info - 48;
	}
	else if (info >= 65 && info <= 70) {
		return info - 55;
	}
	else {
		return 0;
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	return (0);
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
