%{
#include "config_parser.y.h"

int scan_line_count;

void config_scan_init()
{
	scan_line_count = 1;
}
%}
%option noyywrap

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
chroot_user { return CHROOT_USER; }
chroot_group { return CHROOT_GROUP; }
chroot_path { return CHROOT_PATH; }

fastcgi_socket { return FASTCGI_SOCKET; }

include { return INCLUDE; }

\"(\\.|[^\\"])*\" { 
	size_t n = strlen(yytext) - 2;
	strlcpy(yylval.sval, yytext + 1, n + 1);
	return STRING; 
}

[0-9]+ {
	yylval.ival = strtol(yytext, NULL, 0);
	return INTEGER;
}
#.*\n /* comment */
\n { scan_line_count++; }
[ \t\r]+ /* eat whitespace */
"{" { return '{'; }
"}" { return '}'; }

