#define _VERBOSE_
#define _CLOAKED_FILE_PREFIX_

#include "defs.h"

#define MAX_LOGBUF_SIZE 1024

static FILE *outfile = NULL;
static FILE *infile = NULL;

int VERBOSE = 0;

unsigned char CLOAKED_FILE_PREFIX[TIFF_PREFIX_SIZE] = {
	0x4d, 0x4d, 0x00, 0x2a, // TIFF Big Endian format
	0x00, 0x00, 0x00, 0x08, // Offset of the first IFD
	0x00, 0x08,					// There are 8 IFD entries
	0x01, 0x00,					// Tag=ImageWidth (256)
	0x00, 0x04,					//    Type=unsigned long
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x00, 0x00, 0x20, //    Value=32
	0x01, 0x01,					// Tag=ImageLength (257)
	0x00, 0x04,					//    Type=unsigned long
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x00, 0x00, 0x01, //    Value=1
	0x01, 0x02,					// Tag=BitsPerSample (258)
	0x00, 0x03,					//    Type=unsigned short
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x08, 0xff, 0xff, //    Value=8
	0x01, 0x03,					// Tag=ImageCompression (259)
	0x00, 0x03,					//    Type=unsigned short
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x01, 0xff, 0xff, //    Value=1 (none)
	0x01, 0x06,					// Tag=PhotometricInterpretation (262)
	0x00, 0x03,					//    Type=unsigned short
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x01, 0xff, 0xff, //    Value=1 (BlackIsZero)
	0x01, 0x11,					// Tag=StripOffsets (273)
	0x00, 0x03,					//    Type=unsigned short
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x6e, 0xff, 0xff, //    Value=110 (offset to start of strip)
	0x01, 0x16,					// Tag=RowsPerStrip (278)
	0x00, 0x03,					//    Type=unsigned short
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x01, 0xff, 0xff, //    Value=1 (1 row per strip)
	0x01, 0x17,					// Tag=StripByteCounts (279)
	0x00, 0x03,					//    Type=unsigned short
	0x00, 0x00, 0x00, 0x01,	//    Count=1
	0x00, 0x20, 0xff, 0xff, //    Value=32 (same as ImageWidth)
	0x00, 0x00, 0x00, 0x00	// Offset to next IFD (none)
};

/***
	Time-stamp logger
***/
void tslog(const char *arg_fmt, ...) {

	va_list va_array;
	char format[MAX_LOGBUF_SIZE];
	time_t curtime;
	struct tm *loctime;

	curtime = time(NULL);
	loctime = localtime(&curtime);
	strftime(format, MAX_LOGBUF_SIZE, "%Y-%m-%d_%H:%M:%S ", loctime);
	strcat(format, arg_fmt);
	va_start(va_array, arg_fmt);
	vfprintf(stdout, format, va_array);
	va_end(va_array);

}

/***
	Report bad news, cleanup, and exit to OS
***/
void oops(const char *arg_fmt, ...) {

	va_list va_array;
	char format[MAX_LOGBUF_SIZE];

	sprintf(format, "*** Oops, %s", arg_fmt);
	va_start(va_array, arg_fmt);
	vfprintf(stdout, format, va_array);
	va_end(va_array);
	cleanup();
	exit(86);

}

/***
	Cheap-o-cigar byte-string to hex-string dump on stdout
***/
void bytes2hex( char *arg_label, void *arg_bytes, int arg_size ) {

	unsigned char *bptr = (unsigned char *) arg_bytes;
	const int max_cols = 16;	
	char *dots = "................";
	int ndx, nremaining, nfiller;
	char displayable[16];
	char *dptr;
	unsigned long offset = 0;

	printf( "%s:\n\t00000000", arg_label );
	dptr = &displayable[0];
	strcpy( displayable, dots );
	for( ndx = 0; ndx < arg_size; ++ndx ) {
		// If current character printable, use it to replace a dot
		if( isprint( *bptr ) )
			*dptr = *bptr;
		dptr++;
		// Display hex of current char
		printf( " %02x", *bptr++ );
		// Last char of current row?
		if( ( ndx % max_cols ) == (max_cols - 1 ) ) {
			// End of input?
			if( ndx == ( arg_size - 1 ) )
				// Yes - print displayables with just a NL
				printf( " | %s |\n", displayable );
			else {
				// No - print displayable chars, NL, and then start the next line
				offset += 16;
				printf( " | %s |\n\t%08lx", displayable, offset );
				// Re-init displayable char array
				dptr = &displayable[0];
				strcpy( displayable, dots );
			}
		}
	}
	// Check if hex display only a partial
	nremaining = arg_size % max_cols;
	if( nremaining == 0 )
		// No - supply only a NL
		printf( "\n" );
	else {
		// Yes - blank fill hex display on right
		nfiller = max_cols - nremaining;
		for( ndx = 0; ndx < nfiller; ++ndx ) {
			printf( "   " );
			displayable[ nremaining + ndx ] = ' ';
		}
		// Print displayable chars
		printf( " | %s |\n", displayable );
	}
}

/***
	Cleanup
***/
void cleanup () {

	extern CCB ccb;

	int nitems = 0;

	// If cipher handle not yet freed, free it now
	if (ccb.h_cipher != NULL) {
		gcry_cipher_close( ccb.h_cipher );
		ccb.h_cipher = NULL;
		++nitems;
	}

	// If hmac handle not yet freed, free it now
	if (ccb.h_hmac != NULL) {
		gcry_mac_close( ccb.h_hmac );
		ccb.h_hmac = NULL;
		++nitems;
	}

	// If hmac buffer not yet freed, free it now
	if (ccb.hmacbuf != NULL) {
		free( ccb.hmacbuf );
		ccb.hmacbuf = NULL;
		++nitems;
	}

	if( VERBOSE )
		tslog( "cleanup: cleaned up %d CCB items\n", nitems );

	// Close open files if either of them is still open
	input_file_close();
	output_file_close();

}

/***
	Open input file
   ---------------
	Input:
		Input file path
	Output:
		None
***/
void input_file_open(char *arg_filepath) {

	infile = fopen(arg_filepath, "rb");
	if( infile == NULL )
		oops( "input_file_open: Failed to open file {%s}, reason: {%s[%d]}\n",
				arg_filepath, strerror(errno), errno );

	if( VERBOSE )
		tslog( "input_file_open: Opened {%s} for 'rb'\n", arg_filepath );

}

/***
	Read input file
   ---------------
	Input:
		Pointer to output data buffer
		Max size to read
	Output:
		Read size in bytes
			If = max size to read, then read a full buffer
			If <  "    "   "  "  , then read a partial buffer (EOF is next)
			If = 0, then at EOF
***/
size_t input_file_read( void *out_buffer, size_t arg_max_read_size ) {

	size_t bytes_read;

	// Make sure that input_file_open() was already called
	if( infile == NULL )
		oops( "input_file_read: Failed to open file previously\n" );

	// Read file block
	memset( out_buffer, 0xff, arg_max_read_size );
	bytes_read = fread( out_buffer, 1, arg_max_read_size, infile );

	// Return size if full or short block read
	if( bytes_read > 0 )
		return bytes_read;

	// Check for error
	if( ferror( infile ) )
		oops( "input_file_read: Failed to read file, reason: {%s[%d]}\n",
				strerror(errno), errno );

	return 0;  // EOF
}

/***
	Get input file size
***/
size_t input_file_size() {

	size_t here, size_file;

	// Make sure that input_file_open() was already called
	if( infile == NULL )
		oops( "input_file_size: Failed to open file previously\n" );

	// Save current file position
	here = ftell( infile );
	if( here == -1 )
		oops( "input_file_size: ftell() failed, reason: {%s[%d]}\n",
				strerror(errno), errno );

	// Position to EOF
	fseek( infile, 0, SEEK_END );

	// Current position = file size
	size_file = ftell( infile );

	// Reset file position as I found it
	fseek( infile, here, SEEK_SET );

	return size_file;
}

/***
	Close input file
   ----------------
	Input:
		None
	Output:
		None
***/
void input_file_close() {

	if(infile == NULL)
		return;

	fclose(infile);
	infile = NULL;
}

/***
	Open output file
   ----------------
	Input:
		Output file path
	Output:
		None
***/
void output_file_open( char *arg_filepath ) {

	outfile = fopen( arg_filepath, "wb" );
	if(outfile == NULL)
		oops( "output_file_open: Failed to open file {%s}, reason: {%s[%d]}\n",
				arg_filepath, strerror(errno), errno );

	tslog( "output_file_open: Opened {%s} for 'wb'\n", arg_filepath );
}

/***
	Write output file
   -----------------
	Input:
		Pointer to data buffer 
		Exact size to write
	Output:
		None
***/
void output_file_write( void *arg_buffer, size_t arg_write_size ) {
	size_t bytes_wrote;

	// Make sure that output_file_open() was already called
	if( outfile == NULL )
		oops("output_file_write: Failed to open file previously\n");

	// Write file block
	bytes_wrote = fwrite(arg_buffer, 1, arg_write_size, outfile);

	// Return size if full or short block read
	if( bytes_wrote == arg_write_size )
		return;

	// Check for error
	if( ferror(outfile) )
		oops("output_file_write: Failed to write file, reason: {%s[%d]}\n",
				strerror(errno), errno);

	// Impossible short write
	oops( "output_file_write: Short {%d} write makes no sense, expected to write {%d}\n",
			bytes_wrote, arg_write_size );
}

/***
	Close output file
   ----------------
	Input:
		None
	Output:
		None
***/
void output_file_close() {

	if(outfile == NULL)
		return;

	fclose(outfile);
	outfile = NULL;
}

/***
	Read and validate cloaked file prefix
   -------------------------------------
	Input:
		None
	Output:
		None
***/
void read_cloaked_file_prefix() {
	unsigned char buffer[TIFF_PREFIX_SIZE];

	input_file_read( buffer, TIFF_PREFIX_SIZE );
	if( memcmp( CLOAKED_FILE_PREFIX, buffer, TIFF_PREFIX_SIZE ) != 0 )
		oops( "read_cloaked_file_prefix: Not a cloaked file\n" );
}

/***
	Write cloaked file prefix
   -------------------------
	Input:
		None
	Output:
		None
***/
void write_cloaked_file_prefix() {
	output_file_write( CLOAKED_FILE_PREFIX, TIFF_PREFIX_SIZE );
}

