%{
#include <stdlib.h>

static struct git_lfs_config *config;
%}

%union {
	char sval[512];
}

%token BASE_URL
%token REPO
%token ROOT
%token URI
%token STRING

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

