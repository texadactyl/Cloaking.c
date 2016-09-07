#include "defs.h"

// Global variable ccb is accessed outside of this source file.
// Make sure that ccb.{hmacbuf,h_hmac,h_cipher} are all NULL.
CCB ccb = { NULL, NULL, NULL };

/***
	Initialize cloaking operation
	Build a Cipher Control Block (CCB)

	Input:
		Password

	Output:
		CCB populated with:
			Salt
			IV
			AES key
			HMAC key
			HMAC block length
			Handle for HMAC
			Handle for AES cipher
***/
void init_cloaking( char *arg_password ) {

	unsigned char kdf_key[KDF_KEY_SIZE];
	gcry_error_t err;

	time_t tstart, tstop;

	tstart = time(NULL);

	// Scrub CCB
	memset( &ccb, 0x00, sizeof(ccb) );
	ccb.hmacbuf = NULL;
	ccb.h_hmac = NULL;
	ccb.h_cipher = NULL;

	// Generate 128-byte salt in preparation for key derivation
	gcry_create_nonce( ccb.kdf_salt, KDF_SALT_SIZE );
	if( VERBOSE )
		bytes2hex( "init_cloaking: gcry_create_nonce(salt) ok", ccb.kdf_salt, KDF_SALT_SIZE );

	// Key derivation: PBKDF2 using SHA512 w/ 128 byte salt - 50,000 iterations
	// into a 96-byte kdf_key
	err = gcry_kdf_derive(arg_password,
                        strlen(arg_password),
                        GCRY_KDF_PBKDF2,
                        GCRY_MD_SHA512,
                        ccb.kdf_salt,
                        KDF_SALT_SIZE,
                        KDF_ITERATIONS,
                        KDF_KEY_SIZE,
                        kdf_key);
	if( err )
		oops("init_cloaking: gcry_kdf_derive() failed, reason: {%s/%s}\n", 
				gcry_strsource(err), gcry_strerror(err));
	if( VERBOSE )
		bytes2hex( "init_cloaking: gcry_kdf_derive() ok", kdf_key, KDF_KEY_SIZE );

	// Generate the 16-byte initialization vector
	gcry_create_nonce( ccb.aes_iv, AES_IV_SIZE );
	if( VERBOSE )
		bytes2hex( "init_cloaking: gcry_create_nonce(IV) ok", ccb.aes_iv, AES_IV_SIZE );

	// Create cipher handle
	err = gcry_cipher_open( &(ccb.h_cipher),
									GCRY_CIPHER_AES256,
									GCRY_CIPHER_MODE_CBC,
									AES_CBC_OPT );
	if( err )
		oops( "init_cloaking: gcry_cipher_open failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	if( VERBOSE )
		tslog( "init_cloaking: gcry_cipher_open() ok\n" );

	// Set AES cipher key
	err = gcry_cipher_setkey( ccb.h_cipher, kdf_key, AES256_KEY_SIZE );
	if( err )
		oops( "init_cloaking: gcry_cipher_setkey failed, reason {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	if( VERBOSE )
		tslog( "init_cloaking: gcry_cipher_setkey() ok\n" );

	// Set AES cipher IV
	err = gcry_cipher_setiv(ccb.h_cipher, ccb.aes_iv, AES_IV_SIZE);
	if( err )
		oops( "init_cloaking: gcry_cipher_setiv failed, reason {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	if( VERBOSE )
		tslog( "init_cloaking: gcry_cipher_setiv() ok\n" );

	// Compute HMAC length
	ccb.hmac_len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
	if( VERBOSE )
		tslog( "init_cloaking: gcry_mac_get_algo_maclen() ok, len=%ld\n", (long) ccb.hmac_len );

	// Allocate space for HMAC
	ccb.hmacbuf = malloc( ccb.hmac_len );
	if( ccb.hmacbuf == NULL )
		oops( "init_cloaking: unable to allocate enough memory for the HMAC buffer\n");
	if( VERBOSE )
		tslog( "init_cloaking: malloc HMAC buffer ok\n" );

	// Open HMAC
	err = gcry_mac_open(&(ccb.h_hmac), GCRY_MAC_HMAC_SHA512, 0, NULL);
	if( err )
		oops("init_cloaking: gcry_mac_open() failed, reason: {%s/%s}\n", 
				gcry_strsource(err), gcry_strerror(err));
	if( VERBOSE )
		tslog( "init_cloaking: gcry_mac_open() ok\n" );

	// Set HMAC key
	err = gcry_mac_setkey(ccb.h_hmac, &(kdf_key[AES256_KEY_SIZE]), HMAC_KEY_SIZE);
	if( err )
		oops("init_cloaking: gcry_mac_setkey() failed, reason: {%s/%s}\n", 
				gcry_strsource(err), gcry_strerror(err));

	tstop = time(NULL);
	tslog( "init_cloaking: E.T. {%d} seconds\n", tstop - tstart );
}

/***
	Encrypt input file to output file
***/
void proc_cloaking() {

	long bin_size_ctf, size_read, size_write, size_padding, remainder, size_hex;
	size_t obs_hmac_len;
	unsigned char chunk[FILE_CHUNK_SIZE];
	char buffer[80];
	long rchunks = 0L;
	long rbytes = 0L;
	long wbytes = 0L;
	gcry_error_t err;

	time_t tstart, tstop;

	tstart = time(NULL);

	// Write file prefix and update HMAC
	write_cloaked_file_prefix();
	err = gcry_mac_write( ccb.h_hmac, CLOAKED_FILE_PREFIX, sizeof( CLOAKED_FILE_PREFIX ) );
	if( err )
		oops( "proc_cloaking: gcry_mac_write(CLOAKED_FILE_PREFIX) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	wbytes += sizeof( CLOAKED_FILE_PREFIX );

	// Write input (original cleartext) file size as a character string
	// and update HMAC
	bin_size_ctf = input_file_size();
	if( bin_size_ctf < 1 )
		oops( "proc_cloaking: input_file_size() ==> {%ld}; failed to produce a positive number\n", bin_size_ctf );
	sprintf( buffer, FILE_SIZE_FORMAT, bin_size_ctf );
	memcpy( ccb.dec_size_ctf, buffer, FILE_SIZE_STRLEN );
	output_file_write( ccb.dec_size_ctf, FILE_SIZE_STRLEN );
	err = gcry_mac_write( ccb.h_hmac, ccb.dec_size_ctf, FILE_SIZE_STRLEN );
	if( err )
		oops( "proc_cloaking: gcry_mac_write(ccb.dec_size_ctf) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	wbytes += FILE_SIZE_STRLEN;

	// Write KDF salt and update HMAC
	output_file_write( ccb.kdf_salt, KDF_SALT_SIZE );
	err = gcry_mac_write( ccb.h_hmac, ccb.kdf_salt, KDF_SALT_SIZE );
	if( err )
		oops( "proc_cloaking: gcry_mac_write(salt) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	wbytes += KDF_SALT_SIZE;

	// Write AES IV and update HMAC
	output_file_write( ccb.aes_iv, AES_IV_SIZE );
	err = gcry_mac_write(ccb.h_hmac, ccb.aes_iv, AES_IV_SIZE);
	if( err )
		oops( "proc_cloaking: gcry_mac_write(IV) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	wbytes += AES_IV_SIZE;

	// Loop
	for(;;) {
		// Read next file chunk
		size_read = input_file_read( chunk, FILE_CHUNK_SIZE );

		// Break out of loop if EOF
		if( size_read == 0 )
			break;

		// Process input chunk
		rbytes += size_read;
		++rchunks;
		if( VERBOSE ) {
			sprintf( buffer, "DEBUG proc_cloaking: read chunk #%ld size=%ld", rchunks, size_read );
			if( size_read < 64 )
				size_hex = size_read;
			else
				size_hex = 64;
			bytes2hex( buffer, chunk, size_hex ); 
		}

		// If the last block size is not equal to 0 modulo AES_BLOCK_SIZE, pad it
		size_write = size_read;
		if( size_write != FILE_CHUNK_SIZE ) {
			remainder = size_write % AES_BLOCK_SIZE;
			if( remainder != 0 ) {
				size_padding = AES_BLOCK_SIZE - remainder;
				tslog( "proc_cloaking: Padding chunk {%ld} with {%ld} bytes of 0xff\n", rchunks, size_padding );
				while( size_padding-- > 0 )
					chunk[size_write++] = PAD;
			}
		}

		// Encrypt chunk in place
		err = gcry_cipher_encrypt(ccb.h_cipher, chunk, size_write, NULL, 0);
		if( err )
			oops( "proc_cloaking: gcry_cipher_encrypt(chunk) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));

		// Write chunk to output file
		output_file_write( chunk, size_write );
		wbytes += size_write;

		// Accumulate HMAC
		err = gcry_mac_write(ccb.h_hmac, chunk, size_write);
		if( err )
			oops( "proc_cloaking: gcry_mac_write(chunk) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));

	}

	// Finalize MAC and save it in the hmac buffer
	obs_hmac_len = ccb.hmac_len;
	err = gcry_mac_read(ccb.h_hmac, ccb.hmacbuf, (size_t *) &obs_hmac_len);
	if( err )
		oops( "proc_cloaking: gcry_mac_read(finalize) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));

	// Write HMAC
	output_file_write( ccb.hmacbuf, obs_hmac_len );
	wbytes += obs_hmac_len;

	// Report
	tstop = time(NULL);
	tslog( "proc_cloaking: E.T. {%d} seconds\n", tstop - tstart );
	tslog( "proc_cloaking: Read {%ld} bytes in {%ld} chunk(s)\n", rbytes, rchunks );
	tslog( "proc_cloaking: Wrote {%ld} bytes: prefix || Original-size || Salt || IV || ciphertext || HMAC\n", wbytes );

}

