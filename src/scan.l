%{
#include "y.tab.h"
%}
%option noyywrap

%%

base_url { return BASE_URL; }
repo { return REPO; }
root { return ROOT; }
uri { return URI; }

\"(\\.|[^\\"])*\" { 
	strlcpy(yylval.sval, yytext, sizeof(yylval.sval));
	return STRING; 
}

 [ \t\r\n]+ /* eat whitespace */
"{" { return '{'; }
"}" { return '}'; }
