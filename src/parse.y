%{
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "compat/string.h"
#include "htpasswd.h"
#include "configuration.h"

extern int scan_line_count;
static const char *parse_filename;
static struct git_lfs_config *parse_config;
static struct git_lfs_repo *parse_repo;
static uint32_t s_next_id = 0;

int yyerror (const char *msg)
{
	printf("%s:%d: %s\n", parse_filename, scan_line_count, msg);
	return 0;
}

void config_parse_init(const char *filename, struct git_lfs_config *config)
{
	parse_filename = filename;
	parse_config = config;
	parse_repo = NULL;
}
%}

%union {
	char sval[512];
	int ival;
}

%token BASE_URL
%token REPO
%token PORT
%token ROOT
%token URI
%token VERIFY_UPLOAD
%token YES
%token NO
%token FASTCGI_SERVER
%token NUM_THREADS
%token CHROOT_PATH
%token USER
%token GROUP
%token FASTCGI_SOCKET
%token AUTH_REALM
%token ENABLE_AUTHENTICATION
%token AUTH_FILE
%token <ival> INTEGER
%token <sval> STRING
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
	: BASE_URL STRING {
		parse_config->base_url = strndup($2, sizeof($2));
	}
	| CHROOT_PATH STRING {
		parse_config->chroot_path = strndup($2, sizeof($2));	
	}
	| USER STRING {
		parse_config->user = strndup($2, sizeof($2));
	}
	| GROUP STRING {
		parse_config->group = strndup($2, sizeof($2));	
	}
	| PORT INTEGER {
		parse_config->port = $2;
	}
	| NUM_THREADS INTEGER {
		parse_config->num_threads = $2;
	}
	| FASTCGI_SERVER YES {
		parse_config->fastcgi_server = 1;
	}
	| FASTCGI_SERVER NO {
		parse_config->fastcgi_server = 0;
	}
	| FASTCGI_SOCKET STRING {
		parse_config->fastcgi_socket = strndup($2, sizeof($2));	
	}
	| VERIFY_UPLOAD YES {
		parse_config->verify_upload = 1;
	}
	| VERIFY_UPLOAD NO {
		parse_config->verify_upload = 0;
	}
	| INCLUDE STRING
	;

repo_declaration
	: REPO STRING {
		parse_repo = (struct git_lfs_repo *)calloc(1, sizeof(struct git_lfs_repo));
		parse_repo->name = strndup($2, sizeof($2));
		parse_repo->enable_authentication = 1;
		parse_repo->id = s_next_id++;
	}
	'{' repo_params_list '}' {
		SLIST_INSERT_HEAD(&parse_config->repos, parse_repo, entries);
		parse_repo = NULL;
	}
	;

repo_params_list
 	: repo_param repo_params_list
 	| /* empty */
 	;

repo_param
 	: ROOT STRING {
 		parse_repo->root_dir = strndup($2, sizeof($2));	
 	}
 	| URI STRING {
 		parse_repo->uri = strndup($2, sizeof($2));	
 	}
	| ENABLE_AUTHENTICATION YES {
		parse_repo->enable_authentication = 1;
	}
	| ENABLE_AUTHENTICATION NO {
		parse_repo->enable_authentication = 0;
	}
	| AUTH_REALM STRING {
		parse_repo->auth_realm = strndup($2, sizeof($2));
	}
	| AUTH_FILE STRING {
		parse_repo->auth = load_htpasswd_file($2);
		if(!parse_repo->auth) {
			yyerror("Unable to open htpasswd file.");
		}
	}
 	;
