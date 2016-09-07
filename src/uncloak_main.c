#include "defs.h"

static const char *MYNAME = "uncloak";

void show_usage( char *arg_text ) {
	if( arg_text != NULL )
		printf( "\n*** %s\n", arg_text );
	printf( "\nUsage:\t%s\t{cloaked-file}\t{clear-text file}\n", MYNAME );
	exit(1);
}

int main( int argc, char **argv ) {

	char cloaked_file[256];
	char cleartext_file[256];
	char password[256];
	char buffer[256];

	tslog( "%s: version %s\n", MYNAME, VERSION );

	if( --argc < 1)
		show_usage( "Arguments are required" );
	if( strcmp( *++argv, "-h" ) == 0 )
		show_usage( NULL );
	if( strcmp( *argv, "-v" ) == 0 ) {
		VERBOSE = 1;
		++argv;
		--argc;
	}
	if( *(*argv) == '-' ) {
		sprintf( buffer, "Unrecognizable option {%s}", *argv );
		show_usage( buffer );
	}
	if( argc != 3 )
		show_usage( "Wrong number of arguments" );
	strcpy( password, *argv );
	strcpy( cloaked_file, *++argv );
	strcpy( cleartext_file, *++argv );

	input_file_open( cloaked_file );
	output_file_open( cleartext_file );
	init_uncloaking( password );
	proc_uncloaking();
	cleanup();

	tslog( "%s: End\n", MYNAME );
	
	return 0;

}
