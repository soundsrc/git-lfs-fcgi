project(git-lfs-server)

cmake_minimum_required (VERSION 3.0.2)
include(ExternalProject)

find_package(BISON)
find_package(FLEX)

link_directories("${CMAKE_BINARY_DIR}/lib")

ExternalProject_Add(libressl
	SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/libressl"
	CMAKE_ARGS -DENABLE_ASM=OFF -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
	INSTALL_DIR "${CMAKE_BINARY_DIR}"
)

add_library(mongoose STATIC
	"external/mongoose/mongoose.c"
	"external/mongoose/mongoose.h"
)

add_library(json-c STATIC
	"external/json-c/arraylist.c"
	"external/json-c/debug.c"
	"external/json-c/json_c_version.c"
	"external/json-c/json_object.c"
	"external/json-c/json_object_iterator.c"
	"external/json-c/json_tokener.c"
	"external/json-c/json_util.c"
	"external/json-c/linkhash.c"
	"external/json-c/printbuf.c"
	"external/json-c/random_seed.c"
	"external/json-c/arraylist.h"
	"external/json-c/bits.h"
	"external/json-c/debug.h"
	"external/json-c/json.h"
	"external/json-c/json_config.h"
	"external/json-c/json_c_version.h"
	"external/json-c/json_inttypes.h"
	"external/json-c/json_object.h"
	"external/json-c/json_object_iterator.h"
	"external/json-c/json_object_private.h"
	"external/json-c/json_tokener.h"
	"external/json-c/json_util.h"
	"external/json-c/linkhash.h"
	"external/json-c/printbuf.h"
	"external/json-c/random_seed.h"
)

add_library(fcgi STATIC
	"external/libfcgi/libfcgi/fcgiapp.c"
	"external/libfcgi/libfcgi/fcgi_stdio.c"
	"external/libfcgi/libfcgi/os_unix.c"
)
target_include_directories(fcgi PUBLIC
	"external/libfcgi/include"
)

bison_target(ConfigParser src/parse.y ${CMAKE_CURRENT_BINARY_DIR}/config_parser.y.c)
flex_target(ConfigParser src/scan.l ${CMAKE_CURRENT_BINARY_DIR}/config_scanner.l.c)

set(SRC_FILES
	"src/crypt_blowfish.c"
	"src/crypt_blowfish.h"
	"src/configuration.c"
	"src/configuration.h"
	"src/git_lfs_server.c"
	"src/git_lfs_server.h"
	"src/htpasswd.c"
	"src/htpasswd.h"
	"src/httpd.c"
	"src/httpd.h"
	"src/main.c"
	"src/mkdir_recusive.c"
	"src/mkdir_recusive.h"
	"src/oid_utils.c"
	"src/oid_utils.h"
	"src/repo_manager.c"
	"src/repo_manager.h"
	"src/socket_io.h"
	"src/socket_utils.c"
	"src/socket_utils.h"
	"src/parse.y"
	"src/scan.l"
)
if(APPLE)
	list(APPEND SRC_FILES
		"compat/base64.c"
		"compat/explicit_bzero.c"
		"os/unix/droproot.c"
		"os/unix/filesystem.c"
		"os/unix/io.c"
		"os/unix/mutex.c"
		"os/unix/process.c"
		"os/unix/socket.c"
		"os/unix/threads.c"
	)
endif(APPLE)

if(APPLE)
	list(APPEND SRC_FILES
		"os/macosx/sandbox.c"
	)
endif(APPLE)

add_executable(git-lfs-server
	${SRC_FILES}
	${BISON_ConfigParser_OUTPUTS} 
	${FLEX_ConfigParser_OUTPUTS}
)

target_include_directories(git-lfs-server PUBLIC
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}/src"
	"${CMAKE_CURRENT_SOURCE_DIR}/external/libressl/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/external/mongoose"
	"${CMAKE_CURRENT_SOURCE_DIR}/external/json-c"
	"${CMAKE_CURRENT_SOURCE_DIR}/external/libfcgi/include"
)

target_link_libraries(git-lfs-server PUBLIC
	"ssl"
	"crypto"
	"mongoose"
	"json-c"
	"fcgi"
	"pthread"
)

add_dependencies(git-lfs-server libressl)
