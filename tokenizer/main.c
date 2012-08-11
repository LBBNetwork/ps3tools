/*
 * Tokenizer, for making PS3 QA tokens
 *
 * Licensed under GPL v3.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#define QA_FLAG_EXAM_API_ENABLE		0x1
#define QA_FLAG_QA_MODE_ENABLE		0x2
#define QA_FLAG_QA_ADVANCED_ENABLE	0x9
#define QA_FLAG_QA_QA_ADVANCED		0x2
#define QA_FLAG_LV2_UNKNOWN			0x4
#define QA_FLAG_ALLOW_NON_QA		0x1
#define QA_FLAG_FORCE_UPDATE		0x2

unsigned char token_key[] = {
	0x34, 0x18, 0x12, 0x37, 0x62, 0x91, 0x37, 0x1C, 0x8B, 0xC7, 0x56, 0xFF,
	    0xFC, 0x61, 0x15, 0x25, 0x40, 0x3F, 0x95, 0xA8, 0xEF, 0x9D, 0x0C,
	    0x99, 0x64, 0x82, 0xEE, 0xC2, 0x16, 0xB5, 0x62, 0xED
};

unsigned char token_hmac[] = {
	0xCC, 0x30, 0xC4, 0x22, 0x91, 0x13, 0xDB, 0x25, 0x73, 0x35, 0x53, 0xAF,
	0xD0, 0x6E, 0x87, 0x62, 0xB3, 0x72, 0x9D, 0x9E, 0xFA, 0xA6, 0xD5,
	0xF3, 0x5A, 0x6F, 0x58, 0xBF, 0x38, 0xFF, 0x8B, 0x5F, 0x58, 0xA2,
	0x5B, 0xD9, 0xC9, 0xB5, 0x0B, 0x01, 0xD1, 0xAB, 0x40, 0x28, 0x67,
	0x69, 0x68, 0xEA, 0xC7, 0xF8, 0x88, 0x33, 0xB6, 0x62, 0x93, 0x5D,
	0x75, 0x06, 0xA6, 0xB5, 0xE0, 0xF9, 0xD9, 0x7A
};

unsigned char token_iv[] = {
	0xE8, 0x66, 0x3A, 0x69, 0xCD, 0x1A, 0x5C, 0x45, 0x4A, 0x76, 0x1E, 0x72,
	0x8C, 0x7C, 0x25, 0x4E
};

typedef struct _qa_token_v1 {
	uint32_t _m_version;
	uint8_t _m_ps3_psid[0x10];
	uint8_t _m_flags[0x28];
	uint8_t _m_hash[0x14];
} __attribute__ ((__packed__)) qa_token_v1, *qa_token_v1_t;

typedef struct _qa_token_context {
	char *iv;
	char *key;
	char *hmac;
	char *final;
} qa_token_context, *qa_token_context_t;

static inline void hex_to_bytes(const char *hex, uint8_t ** buffer,
				size_t * bytes)
{
	*bytes = strlen(hex) / 2;
	*buffer = (uint8_t *) malloc(*bytes);
	size_t i;
	for (i = 0; i < *bytes; i++) {
		uint32_t byte;
		sscanf(hex, "%2x", &byte);
		(*buffer)[i] = byte;
		hex += 2;
	}
}

int main(int argc, char *argv[])
{
	qa_token_v1 token;
	unsigned char buffer[80];
	unsigned char tmpbuf[80 - 0x14];
	uint8_t *hmac, *psid = NULL;
	int flags[3] = {0, 0, 0};
	size_t bytes = 0;
	int i, j = 0, c;
	AES_KEY aes_key;

	while ((c = getopt(argc, argv, "a:b:c:p:")) != -1) {
		switch(c) {
			case 'a':
				flags[0] = atoi(optarg);
				break;
			case 'b':
				flags[1] = atoi(optarg);
				break;
			case 'c':
				flags[2] = atoi(optarg);
				break;
			case 'p':
				hex_to_bytes(optarg, (uint8_t**)&psid, &bytes);
				break;
			default:
				printf("%s [-abcp] [flags/[psid if -p]]\n", argv[0]);
				break;
		}
	}

	memset(&token, 0, 80);

	/* init constants */
	token._m_version = __builtin_bswap32(1);

	/* hash */
	if (bytes != 0x10) {
		printf("psid MUST be 0x10 long or not supplied!!!\n");
		abort();
	}

	memcpy(token._m_ps3_psid, psid, bytes);

	token._m_flags[0x13] |= flags[0];
	token._m_flags[0x1b] |= flags[1];
	token._m_flags[0x1f] |= flags[2];

	memcpy(tmpbuf, &token, 80 - 0x14);

	hmac =
	    HMAC(EVP_sha1(), token_hmac, sizeof(token_hmac), tmpbuf, 80 - 0x14,
		 NULL, NULL);
	memcpy(token._m_hash, hmac, 0x14);

	/* encrypt */
	memcpy(buffer, &token, 80);

    AES_set_encrypt_key(token_key, 256, &aes_key);
    AES_cbc_encrypt((uint8_t*)&token, buffer, 80, &aes_key, token_iv, AES_ENCRYPT);

	for (i = 0; i < 80; i++) {
		if (j++ % 8 == 0) {
			printf("\n ");
		}
		printf("0x%02x, ", buffer[i]);
	}
	printf("\n");

	return 0;

}
