#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	 if(entropy != NULL) {
		 unsigned char* outBuf_64;
		 outBuf_64 = malloc(64);
		 HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, outBuf_64, NULL);

		 for(int i=0; i<32; i++) {
			 K->hmacKey[i] = outBuf_64[i]   ;
			 K->aesKey[i]  = outBuf_64[i+32];
		 }

		 free(outBuf_64);
	 } else {
		 unsigned char* outBuf_32_hmac;
		 unsigned char* outBuf_32_aes ;
		 outBuf_32_hmac = malloc(32);
		 outBuf_32_aes  = malloc(32);
		 randBytes(outBuf_32_hmac, 32);
		 randBytes(outBuf_32_aes , 32);

		 for(int i=0; i<32; i++) {
			 K->hmacKey[i] = outBuf_32_hmac[i];
			 K->aesKey[i]  = outBuf_32_aes[i] ;
		 }

		 free(outBuf_32_hmac);
		 free(outBuf_32_aes );
	 }

	 return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	 if(IV == NULL) {
		 for(int i=0; i<16; i++) { IV[i] = i;}
	 }
	 memcpy(outBuf, IV, 16);

	 EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	 if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV)) {
		 ERR_print_errors_fp(stderr);
	 }
	 int nWritten;
	 if(1 != EVP_EncryptUpdate(ctx, outBuf+16, &nWritten, inBuf, len)) {
		 ERR_print_errors_fp(stderr);
	 }
	 EVP_CIPHER_CTX_free(ctx);

	 int totalLen = 16 + nWritten + 32;
	 unsigned char newBuf[nWritten];
	 memcpy(newBuf, &outBuf[16], nWritten);

	 unsigned char* HMAC_Buf = malloc(32);
	 HMAC(EVP_sha256(), K->hmacKey, 32, outBuf, nWritten+16, HMAC_Buf, NULL);
	 memcpy(&outBuf[nWritten+16], HMAC_Buf, 32);

	 return totalLen; /* TODO: should return number of bytes written, which
	             				 hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	return 0;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
