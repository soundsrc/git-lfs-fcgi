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
	strlcpy(yylval.sval, yytext, sizeof(yylval.sval));
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
