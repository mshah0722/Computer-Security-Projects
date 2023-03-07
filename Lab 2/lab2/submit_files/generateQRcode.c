#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

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

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// Encode the secret hex by using a for loop for uint8 for first 10 chars
	// and then the given base32 function
	uint8_t t[10];
	char secretHexConvert[17];

	for (int i = 0; i < 10; i++) {
		t[i] = 16 * to_int(secret_hex[i*2]) + to_int(secret_hex[i*2+1]);
	}

	assert(base32_encode(t, 10, secretHexConvert, 16) != -1);
	secretHexConvert[16] = '\0';

	// Chose arbitrary length for the URL... not sure if this is the best practice though
	char url[300];

	sprintf(url, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", 
		urlEncode(accountName), urlEncode(issuer),
		secretHexConvert);

	displayQRcode(url);

	return (0);
}
