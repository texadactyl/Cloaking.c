#ifndef _DEFS_
#define _DEFS_

#include <errno.h>
#include <gcrypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#define VERSION "1.0"

#define AES256_KEY_SIZE		32
#define AES_IV_SIZE   		16
#define AES_BLOCK_SIZE 		16
// Buggy (2016-09-02): #define AES_CBC_OPT			GCRY_CIPHER_CBC_CTS
#define AES_CBC_OPT			0
#define FILE_CHUNK_SIZE		4096
#define FILE_SIZE_FORMAT	"%016ld"
#define FILE_SIZE_STRLEN	16
#define HMAC_KEY_SIZE		64
#define KDF_ITERATIONS		50000
#define KDF_KEY_SIZE			AES256_KEY_SIZE + HMAC_KEY_SIZE
#define KDF_SALT_SIZE		128
#define PAD						0xff
#define TIFF_PREFIX_SIZE 	110

typedef struct {
	/* Some elements need a cleanup before exiting due to heap allocations */
	/* Start of cleanup list */
	unsigned char *hmacbuf;		// Pointer to HMAC buffer byte array
	gcry_cipher_hd_t h_cipher; // Handle for AES cipher operations (pointer)
	gcry_mac_hd_t h_hmac;		// Handle for HMAC operations (pointer)
	/* End of cleanup list */
	size_t hmac_len;
	unsigned char kdf_salt[KDF_SALT_SIZE]; // KDF Salt
	unsigned char aes_iv[AES_IV_SIZE]; // AES initialization vector
	unsigned char dec_size_ctf[FILE_SIZE_STRLEN]; // decimal byte count of clear text file
} CCB;

// common.c
void bytes2hex( char *arg_label, void *arg_bytes, int arg_size );
void cleanup();
void input_file_close();
void input_file_open( char *arg_filepath );
size_t input_file_read( void *out_buffer, size_t arg_max_read_size );
size_t input_file_size();
void oops( const char *arg_fmt, ... );
void output_file_close();
void output_file_open( char *arg_filepath );
void output_file_write( void *arg_buffer, size_t arg_write_size );
void read_cloaked_file_prefix();
void write_cloaked_file_prefix();
void tslog( const char *arg_fmt, ... );

// cloak_helpers.c
void proc_cloaking();
void init_cloaking( char *arg_password );

// uncloak_helpers.c
void proc_uncloaking();
void init_uncloaking( char *arg_password );

#endif

#ifndef _VERBOSE_
extern int VERBOSE;
#endif

#ifndef _CLOAKED_FILE_PREFIX_
extern unsigned char CLOAKED_FILE_PREFIX[TIFF_PREFIX_SIZE];
#endif


