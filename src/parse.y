%{
#include <stdlib.h>

static struct git_lfs_config *config;
%}

%union {
	char sval[512];
	int ival;
}

%token BASE_URL
%token REPO
%token ROOT
%token URI
%token NUM_THREADS
%token CHROOT
%token CHROOT_USER
%token CHROOT_GROUP
%token SOCKET
%token INTEGER
%token STRING
%token INCLUDE

%%

config
	: declarations
	;

declarations
	: global_declaration declarations
	| repo_declaration declarations
	| /* empty */
	;

global_declaration
	: BASE_URL STRING
	| CHROOT STRING
	| CHROOT_USER STRING
	| CHROOT_GROUP STRING
	| NUM_THREADS INTEGER
	| SOCKET STRING
	| INCLUDE STRING
	;

repo_declaration
	: REPO STRING '{' repo_params_list '}'
	;

repo_params_list
 	: repo_param repo_params_list
 	| /* empty */
 	;

repo_param
 	: ROOT STRING
 	| URI STRING
 	;
