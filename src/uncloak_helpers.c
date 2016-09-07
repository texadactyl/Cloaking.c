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
void init_uncloaking( char *arg_password ) {

	unsigned char kdf_key[KDF_KEY_SIZE];
	char dec_bytesize[FILE_SIZE_STRLEN+1];
	gcry_error_t err;
	size_t size_read;

	time_t tstart, tstop;

	tstart = time(NULL);

	// Scrub CCB
	memset( &ccb, 0x00, sizeof(ccb) );
	ccb.hmacbuf = NULL;
	ccb.h_hmac = NULL;
	ccb.h_cipher = NULL;

	// Read prefix
	read_cloaked_file_prefix();
	if( VERBOSE )
		bytes2hex( "init_uncloaking: read prefix ok", CLOAKED_FILE_PREFIX, sizeof( CLOAKED_FILE_PREFIX ) );

	// Read decimal-coded cleartext file size (to be the size of the output file)
	size_read = input_file_read( ccb.dec_size_ctf, FILE_SIZE_STRLEN );
	if( size_read != FILE_SIZE_STRLEN )
		oops( "init_uncloaking: input_file_read(ccb.dec_size_ctf) returned {%d} bytes\n", size_read );
	if( VERBOSE )
		bytes2hex( "init_uncloaking: read ccb.dec_size_ctf ok", dec_bytesize, FILE_SIZE_STRLEN );

	// Read 128-byte salt from input file in preparation for key derivation
	size_read = input_file_read( ccb.kdf_salt, KDF_SALT_SIZE );
	if( size_read != KDF_SALT_SIZE )
		oops( "init_uncloaking: input_file_read(salt) returned {%d} bytes\n", size_read );
	if( VERBOSE )
		bytes2hex( "init_uncloaking: read salt ok", ccb.kdf_salt, KDF_SALT_SIZE );

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
	if( err ) {
		cleanup();
		oops("init_uncloaking: gcry_kdf_derive() failed, reason: {%s/%s}\n", 
				gcry_strsource(err), gcry_strerror(err));
	}
	if( VERBOSE )
		bytes2hex( "init_uncloaking: gcry_kdf_derive() ok", kdf_key, KDF_KEY_SIZE );

	// Read the 16-byte initialization vector
	size_read = input_file_read( ccb.aes_iv, AES_IV_SIZE );
	if( size_read != AES_IV_SIZE )
		oops( "init_uncloaking: input_file_read(IV) returned {%d} bytes\n", size_read );
	if( VERBOSE )
		bytes2hex( "init_uncloaking: read IV ok", ccb.aes_iv, AES_IV_SIZE );

	// Create cipher handle
	err = gcry_cipher_open( &(ccb.h_cipher),
									GCRY_CIPHER_AES256,
									GCRY_CIPHER_MODE_CBC,
									AES_CBC_OPT );
	if( err ) {
		cleanup();
		oops( "init_uncloaking: gcry_cipher_open failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}
	if( VERBOSE )
		tslog( "init_uncloaking: gcry_cipher_open() ok\n" );

	// Set AES cipher key
	err = gcry_cipher_setkey( ccb.h_cipher, kdf_key, AES256_KEY_SIZE );
	if( err ) {
		cleanup();
		oops( "init_uncloaking: gcry_cipher_setkey failed, reason {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}
	if( VERBOSE )
		tslog( "init_uncloaking: gcry_cipher_setkey() ok\n" );

	// Set AES cipher IV
	err = gcry_cipher_setiv(ccb.h_cipher, ccb.aes_iv, AES_IV_SIZE);
	if( err ) {
		cleanup();
		oops( "init_uncloaking: gcry_cipher_setiv failed, reason {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}
	if( VERBOSE )
		tslog( "init_uncloaking: gcry_cipher_setiv() ok\n" );

	// Compute HMAC length
	ccb.hmac_len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
	if( VERBOSE )
		tslog( "init_uncloaking: gcry_mac_get_algo_maclen() ok, len=%ld\n", (long) ccb.hmac_len );

	// Allocate space for HMAC
	ccb.hmacbuf = malloc( ccb.hmac_len );
	if( ccb.hmacbuf == NULL ) {
		cleanup();
		oops( "init_uncloaking: unable to allocate enough memory for the HMAC buffer\n");
	}
	if( VERBOSE )
		tslog( "init_uncloaking: malloc HMAC buffer ok\n" );

	// Open HMAC
	err = gcry_mac_open(&(ccb.h_hmac), GCRY_MAC_HMAC_SHA512, 0, NULL);
	if( err ) {
		cleanup();
		oops("init_uncloaking: gcry_mac_open() failed, reason: {%s/%s}\n", 
				gcry_strsource(err), gcry_strerror(err));
	}
	if( VERBOSE )
		tslog( "init_uncloaking: gcry_mac_open() ok\n" );

	// Set HMAC key
	err = gcry_mac_setkey(ccb.h_hmac, &(kdf_key[AES256_KEY_SIZE]), HMAC_KEY_SIZE);
	if( err ) {
		cleanup();
		oops("init_uncloaking: gcry_mac_setkey() failed, reason: {%s/%s}\n", 
				gcry_strsource(err), gcry_strerror(err));
	}

	tstop = time(NULL);
	tslog( "init_uncloaking: E.T. {%d} seconds\n", tstop - tstart );
}

/***
	Decrypt input file to output file
***/
void proc_uncloaking () {

	unsigned char chunk[FILE_CHUNK_SIZE];
	long rchunks = 0L;
	long rbytes = 0L;
	long wbytes = 0L;
	size_t bin_size_ctf, size_cleartext, size_ciphertext, size_read, size_chunk, size_write, size_padding, size_hex;
	unsigned long temp_ulong;
	gcry_error_t err;
	char label[80];

	time_t tstart, tstop;

	tstart = time(NULL);

	// Update HMAC with CLOAKED_FILE_PREFIX
	err = gcry_mac_write( ccb.h_hmac, CLOAKED_FILE_PREFIX, sizeof( CLOAKED_FILE_PREFIX ) );
	if( err ) {
		cleanup();
		oops( "proc_uncloaking: gcry_mac_write(CLOAKED_FILE_PREFIX) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}
	rbytes += sizeof( CLOAKED_FILE_PREFIX );

	// Update HMAC with ccb.dec_size_ctf
	err = gcry_mac_write( ccb.h_hmac, ccb.dec_size_ctf, FILE_SIZE_STRLEN );
	if( err ) {
		cleanup();
		oops( "proc_uncloaking: gcry_mac_write(ccb.dec_size_ctf) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}
	rbytes += FILE_SIZE_STRLEN;

	// Get a binary form (bin_size_ctf) of ccb.dec_size_ctf for later
	sscanf( (char *) ccb.dec_size_ctf, "%ld", &temp_ulong );
	bin_size_ctf = (size_t) temp_ulong;
	if( VERBOSE )
		tslog( "init_uncloaking: Byte-count of the original cleartext file is {%ld}\n", bin_size_ctf );

	// Update HMAC with KDF salt
	err = gcry_mac_write( ccb.h_hmac, ccb.kdf_salt, KDF_SALT_SIZE );
	if( err ) {
		cleanup();
		oops( "proc_uncloaking: gcry_mac_write(salt) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}
	rbytes += KDF_SALT_SIZE;

	// Update HMAC with AES IV
	err = gcry_mac_write(ccb.h_hmac, ccb.aes_iv, AES_IV_SIZE);
	if( err ) {
		cleanup();
		oops( "proc_uncloaking: gcry_mac_write(IV) failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err) );
	}
	rbytes += AES_IV_SIZE;

	// Compute total size of imbedded ciphertext (possibly, padded)	
	size_cleartext = bin_size_ctf;
	size_padding = AES_BLOCK_SIZE - ( bin_size_ctf % AES_BLOCK_SIZE );
	size_ciphertext = bin_size_ctf + size_padding;
	tslog( "proc_uncloaking: Significant size of imbedded ciphertext is {%ld}\n", bin_size_ctf );
	tslog( "proc_uncloaking: Padded size of imbedded ciphertext is {%ld}\n", size_ciphertext );

	// Loop for all imbedded ciphertext	
	for( ; size_cleartext > 0 ; ) {

		// Adjust chunk read size
		if( size_ciphertext < FILE_CHUNK_SIZE )
			size_chunk = size_ciphertext;
		else
			size_chunk = FILE_CHUNK_SIZE;

		// Read next file chunk
		size_read = input_file_read( chunk, size_chunk );
		if( size_read != size_chunk ) {
			cleanup();
			oops( "proc_uncloaking: proc_uncloaking: input_file_read(chunk) failed on chunk {#%ld}, chunk size {%ld}, read size {%ld}\n", rchunks, size_chunk, size_read );
		}
		rbytes += size_chunk;
		++rchunks;

		// Accumulate HMAC
		err = gcry_mac_write(ccb.h_hmac, chunk, size_chunk);
		if( err ) {
			cleanup();
			oops( "proc_uncloaking: gcry_mac_write(chunk) failed on chunk {#%ld}, reason: {%s/%s}\n", rchunks, gcry_strsource(err), gcry_strerror(err));
		}

		// Decrypt chunk in place
		err = gcry_cipher_decrypt(ccb.h_cipher, chunk, size_chunk, NULL, 0);
		if( err ) {
			cleanup();
			oops( "proc_uncloaking: gcry_cipher_decrypt failed on chunk {#%ld}, reason: {%s/%s}\n", rchunks, gcry_strsource(err), gcry_strerror(err));
		}

		if( VERBOSE ) {
			sprintf( label, "DEBUG proc_uncloaking: decrypted chunk #%ld size=%ld", rchunks, size_chunk );
			if( size_chunk < 64 )
				size_hex = size_chunk;
			else
				size_hex = 64;
			bytes2hex( label, chunk, size_hex ); 
		}

		// If this is the last block and it contains contains padding, adjust write size to exclude pad characters
		size_write = size_chunk;
		if( size_cleartext < FILE_CHUNK_SIZE ) {
			if( size_padding != 0 ) {
				size_write -= size_padding;
				if( VERBOSE )
					tslog( "DEBUG proc_uncloaking: Adjusted last block write size from {%ld} to {%ld}\n", size_chunk, size_write );
			}
		}

		// Write decrypted chunk to output file
		output_file_write( chunk, size_write );
		wbytes += size_chunk;
		size_cleartext -= size_write;
		size_ciphertext -= size_write;

	}

	// Read HMAC
	size_read = input_file_read( ccb.hmacbuf, ccb.hmac_len );
	if( size_read != ccb.hmac_len ) {
		cleanup();
		oops( "proc_uncloaking: input_file_read(HMAC) failed after chunk {#%ld}, HMAC size {%ld}, read size {%ld}\n", rchunks, ccb.hmac_len, size_read );
	}
	rbytes += ccb.hmac_len;

	// Verify MAC
	err = gcry_mac_verify( ccb.h_hmac, ccb.hmacbuf, ccb.hmac_len );
	if( err ) {
		cleanup();
		oops( "proc_uncloaking: gcry_mac_verify() failed, reason: {%s/%s}\n", gcry_strsource(err), gcry_strerror(err));
	}

	// Report
	tstop = time(NULL);
	tslog( "proc_uncloaking: E.T. {%d} seconds\n", tstop - tstart );
	tslog( "proc_uncloaking: Read {%ld} bytes including {%ld} ciphertext chunks of total bytesize {%ld}\n", rbytes, rchunks, bin_size_ctf );
	tslog( "proc_uncloaking: Wrote {%ld} bytes of cleartext\n", wbytes );

}

