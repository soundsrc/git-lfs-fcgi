%{
#include <stdlib.h>

static const char *parse_filename;
static struct git_lfs_config *parse_config;
static struct git_lfs_repo *parse_repo;

void parse_init(const char *filename, struct git_lfs_config *config)
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
%token ROOT
%token URI
%token VERIFY_UPLOAD
%token YES
%token NO
%token NUM_THREADS
%token CHROOT_PATH
%token CHROOT_USER
%token CHROOT_GROUP
%token SOCKET
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
	| CHROOT_USER STRING {
		parse_config->chroot_user = strndup($2, sizeof($2));	
	}
	| CHROOT_GROUP STRING {
		parse_config->chroot_group = strndup($2, sizeof($2));	
	}
	| NUM_THREADS INTEGER {
		parse_config->num_threads = $2;
	}
	| SOCKET STRING {
		parse_config->socket = strndup($2, sizeof($2));	
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
 	;
