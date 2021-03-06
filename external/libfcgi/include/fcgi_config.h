/* 
 *  Copied to fcgi_config.h when building on WinNT without cygwin,
 *  i.e. configure is not run.  See fcgi_config.h.in for details.
 */

#define HAVE_FPOS 1
#define HAVE_LIMITS_H 1
#define HAVE_STREAMBUF_CHAR_TYPE 1
#define HAVE_STRERROR 1
#undef HAVE_ARPA_INET_H
#undef HAVE_DLFCN_H
#undef HAVE_FILENO_PROTO
#undef HAVE_INTTYPES_H
#undef HAVE_IOSTREAM_WITHASSIGN_STREAMBUF
#undef HAVE_LIBNSL
#undef HAVE_LIBSOCKET
#undef HAVE_MEMORY_H
#undef HAVE_NETDB_H
#undef HAVE_NETINET_IN_H
#undef HAVE_PTHREAD
#undef HAVE_SOCKADDR_UN_SUN_LEN
#undef HAVE_SOCKLEN
#undef HAVE_STDINT_H
#undef HAVE_STDLIB_H
#undef HAVE_STRING_H
#undef HAVE_STRINGS_H
#undef HAVE_SYS_PARAM_H
#undef HAVE_SYS_SOCKET_H
#undef HAVE_SYS_STAT_H
#undef HAVE_SYS_TIME_H
#undef HAVE_SYS_TYPES_H
#undef HAVE_UNISTD_H
#undef HAVE_VA_ARG_LONG_DOUBLE_BUG
#undef PTHREAD_CREATE_JOINABLE
#undef STDC_HEADERS
#undef USE_LOCKING
#undef const
#undef inline
#undef ssize_t

#ifdef __linux__
#	define HAVE_ARPA_INET_H 1
#	define HAVE_DLFCN_H 1
#	define HAVE_FILENO_PROTO 1
//	#define HAVE_FPOS 1
#	define HAVE_INTTYPES_H 1
#	define HAVE_LIBNSL 1
//	#define HAVE_LIMITS_H 1
#	define HAVE_MEMORY_H 1
#	define HAVE_NETDB_H 1
#	define HAVE_NETINET_IN_H 1
#	define HAVE_STDINT_H 1
#	define HAVE_STDLIB_H 1
//	#define HAVE_STREAMBUF_CHAR_TYPE 1
//	#define HAVE_STRERROR 1
#	define HAVE_STRINGS_H 1
#	define HAVE_STRING_H 1
#	define HAVE_SYS_PARAM_H 1
#	define HAVE_SYS_SOCKET_H 1
#	define HAVE_SYS_STAT_H 1
#	define HAVE_SYS_TIME_H 1
#	define HAVE_SYS_TYPES_H 1
#	define HAVE_UNISTD_H 1
#	define PACKAGE "fcgi"
#	define STDC_HEADERS 1
#	define VERSION "2.4.0"
#else
#	ifndef _MSC_VER
#		define STDC_HEADERS 1
#		define HAVE_FILENO_PROTO 1
#		define HAVE_NETINET_IN_H 1
#		define HAVE_NETDB_H 1
#		define HAVE_SYS_SOCKET_H 1
#		define HAVE_UNISTD_H 1
#		define HAVE_SOCKADDR_UN_SUN_LEN 1
#	endif
#endif

#ifdef __APPLE__
#define HAVE_SOCKLEN
#endif
