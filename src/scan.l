%{
#include <stdio.h>
#include "os/filesystem.h"
#include "compat/queue.h"
#include "config_parser.y.h"

struct scan_state
{
	SLIST_ENTRY(scan_state) entry;
	FILE *file;
	char *filename;
	int line_count;
};

SLIST_HEAD(scan_state_stack, scan_state) scan_stack;

int yyerror (const char *msg)
{
	struct scan_state *head = SLIST_FIRST(&scan_stack);
	if(head)
	{
		printf("%s:%d: %s\n", head->filename, head->line_count, msg);
	}
	else
	{
		printf("%s\n", msg);
	}
	return 0;
}

int config_scan_push_file(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	if(!fp)
	{
		fprintf(stderr, "%s: Cannot open file.\n", filename);
		return 0;
	}
	
	struct scan_state *state = calloc(1, sizeof *state);
	state->filename = strdup(filename);
	state->line_count = 1;
	state->file = fp;
	SLIST_INSERT_HEAD(&scan_stack, state, entry);
	
	yyin = fp;
	yypush_buffer_state(yy_create_buffer( yyin, YY_BUF_SIZE ));
	
	return 1;
}

int config_scan_pop_file()
{
	struct scan_state *state = SLIST_FIRST(&scan_stack);
	if(!state)
	{
		return 0;
	}
	
	yypop_buffer_state();
	
	SLIST_REMOVE_HEAD(&scan_stack, entry);
	
	fclose(state->file);
	free(state->filename);
	free(state);
	
	return 1;
}


void config_scan_init(const char *filename)
{
	config_scan_push_file(filename);
}

static void config_scan_increment_line_count()
{
	struct scan_state *state = SLIST_FIRST(&scan_stack);
	if(state)
	{
		state->line_count++;
	}
}

%}
%option noyywrap

%x incl
%%

base_url { return BASE_URL; }
repo { return REPO; }
num_threads { return NUM_THREADS; }
fastcgi_server { return FASTCGI_SERVER; }
port { return PORT; }
root { return ROOT; }
uri { return URI; }
verify_upload { return VERIFY_UPLOAD; }
yes { return YES; }
no { return NO; }
user { return USER; }
group { return GROUP; }
chroot_path { return CHROOT_PATH; }

enable_authentication { return ENABLE_AUTHENTICATION; }
auth_realm { return AUTH_REALM; }
auth_file { return AUTH_FILE; }

fastcgi_socket { return FASTCGI_SOCKET; }

include { BEGIN(incl); }

\"(\\.|[^\\"])*\" { 
	size_t n = strlen(yytext) - 2;
	strlcpy(yylval.sval, yytext + 1, n + 1);
	return STRING; 
}

[0-9]+ {
	yylval.ival = strtol(yytext, NULL, 0);
	return INTEGER;
}
#.*\n { config_scan_increment_line_count(); } /* comment */
\n { config_scan_increment_line_count(); }
[ \t\r]+ /* eat whitespace */
"{" { return '{'; }
"}" { return '}'; }

. { return yytext[0]; }

<incl>#.*\n { config_scan_increment_line_count(); } /* comment */
<incl>\n { config_scan_increment_line_count(); }
<incl>[ \t\r]+ /* eat whitespace */
<incl>\"(\\.|[^\\"])*\" {
	yytext[strlen(yytext) - 1] = 0;
	const char *inc_pattern = yytext + 1;
	int num_files;
	const char **file_list = os_glob(inc_pattern, &num_files);
	if(!file_list)
	{
		yyerror("Unable to include files.");
	}
	else
	{
		for(int i = num_files - 1; i >= 0; --i)
		{
			config_scan_push_file(file_list[i]);
		}
		free(file_list);
	}
	BEGIN(INITIAL);
}

<<EOF>> {
	config_scan_pop_file();
	if (!YY_CURRENT_BUFFER )
	{
		yyterminate();
	}
}
