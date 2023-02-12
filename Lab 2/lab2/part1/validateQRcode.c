#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#include "time.h"
#define FULL 0x00ff

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
	uint8_t secretKey[64];
	uint8_t innerKey[64];
	uint8_t outerKey[64];

	memset(secretKey, 0, 64);
	for (int i = 0; i < 10; i++){
		secretKey[i] = 16 * to_int(secret_hex[i*2]) + to_int(secret_hex[i*2+1]);
	}

	memset(innerKey, 0x36, 64);
	memset(outerKey, 0x5c, 64);

	// XOR the inner and outer keys respectively with the secret key
	for (int i = 0; i < 64; i++) {
		innerKey[i] = secretKey[i] ^ innerKey[i];
	}

	for (int i = 0; i < 64; i++) {
                outerKey[i] = secretKey[i] ^ outerKey[i];
        }

	// Current UNIX time over the active period of the TOTP
	uint64_t timePeriod = time(NULL)/30;
	
	uint8_t message[8];
	
	for(int i = 0; i < 8; i++){
		message[7-i] = (timePeriod >> (i * 8)) & FULL;
	}

	// HMAC Calculation
	SHA1_INFO ctx;


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
