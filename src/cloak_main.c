#include "defs.h"

static const char *MYNAME = "cloak";

void show_usage( char *arg_text ) {
	if( arg_text != NULL )
		printf( "\n*** %s\n", arg_text );
	printf( "\nUsage:\t%s\t{clear-text file}\t{cloaked-file}\n", MYNAME );
	exit(1);
}

int main( int argc, char **argv ) {

	char cleartext_file[256];
	char cloaked_file[256];
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
	strcpy( cleartext_file, *++argv );
	strcpy( cloaked_file, *++argv );

	input_file_open( cleartext_file );
	output_file_open( cloaked_file );
	init_cloaking( password );
	proc_cloaking();
	cleanup();

	tslog( "%s: End\n", MYNAME );

}
