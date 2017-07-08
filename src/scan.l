%{
#include "y.tab.h"

static int scan_line_count;

static void scan_init()
{
	scan_line_count = 1;
}
%}
%option noyywrap

%%

base_url { return BASE_URL; }
repo { return REPO; }
num_threads { return NUM_THREADS; }
root { return ROOT; }
uri { return URI; }

chroot_user { return CHROOT_USER; }
chroot_group { return CHROOT_GROUP; }
chroot { return CHROOT; }

socket { return SOCKET; }

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
 [ \t\r\n]+ /* eat whitespace */
"{" { return '{'; }
"}" { return '}'; }
\n { scan_line_count++; }