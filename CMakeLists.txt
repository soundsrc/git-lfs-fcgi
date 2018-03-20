project(git-lfs-fcgi)

cmake_minimum_required (VERSION 3.0.2)
include(ExternalProject)
include(FindOpenSSL)

find_package(BISON)
find_package(FLEX)

find_library(SQLITE3_LIBRARY NAMES sqlite3 libsqlite3)
find_library(LIBFCGI_LIBRARY NAMES fcgi libfcgi)
find_library(JSONC_LIBRARY NAMES json-c libjson-c)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set(LINUX TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	set(FREEBSD TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	set(OPENBSD TRUE)
endif()

if(LINUX OR FREEBSD OR OPENBSD)
	set(CMAKE_C_FLAGS "-std=gnu99")
endif()

link_directories("${CMAKE_BINARY_DIR}/lib")

SET(INC_DIRS
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}/src"
	"${CMAKE_CURRENT_SOURCE_DIR}/external/mongoose",
	"/usr/local/include"
)

set(LIB_FILES
        "mongoose"
        "pthread")

if(OPENSSL_FOUND)
	list(APPEND INC_DIRS ${OPENSSL_INCLUDE_DIR})
        list(APPEND LIB_FILES ${OPENSSL_LIBRARIES})
else()
	ExternalProject_Add(libressl
		SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/libressl"
		CMAKE_ARGS -DENABLE_ASM=OFF -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
		INSTALL_DIR "${CMAKE_BINARY_DIR}"
	)
	list(APPEND INC_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/external/libressl/include")
        list(APPEND LIB_FILES "ssl" "crypto")
endif()

add_library(mongoose STATIC
	"external/mongoose/mongoose.c"
	"external/mongoose/mongoose.h"
)

if (JSONC_LIBRARY)
	list(APPEND LIB_FILES "${JSONC_LIBRARY}")
else()
	add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/external/json-c" EXCLUDE_FROM_ALL)
	list(APPEND INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/json-c")
	list(APPEND LIB_FILES "json-c-static")
endif()

if (SQLITE3_LIBRARY)
	list(APPEND LIB_FILES "${SQLITE3_LIBRARY}")
else()
	add_library(sqlite3 STATIC
		"external/sqlite/sqlite3.c"
		"external/sqlite/sqlite3.h"
	)
	list(APPEND INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/sqlite")
	list(APPEND LIB_FILES "sqlite3")
endif()

if (LIBFCGI_LIBRARY)
	 list(APPEND LIB_FILES "${LIBFCGI_LIBRARY}")
else()
	add_library(fcgi STATIC
		"external/libfcgi/libfcgi/fcgiapp.c"
		"external/libfcgi/libfcgi/fcgi_stdio.c"
		"external/libfcgi/libfcgi/os_unix.c"
	)

	target_include_directories(fcgi PUBLIC
		"external/libfcgi/include"
	)
        list(APPEND INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/libfcgi/include")
        list(APPEND LIB_FILES "fcgi")
endif()

bison_target(ConfigParser src/parse.y ${CMAKE_CURRENT_BINARY_DIR}/config_parser.y.c)
flex_target(ConfigParser src/scan.l ${CMAKE_CURRENT_BINARY_DIR}/config_scanner.l.c)

set(SRC_FILES
	"os/droproot.h"
	"os/filesystem.h"
	"os/io.h"
	"os/mutex.h"
	"os/process.h"
	"os/socket.h"
	"os/threads.h"
	"os/signal.h"
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
if(UNIX)
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
		"os/unix/signal.c"
	)
endif(UNIX)

if(APPLE)
	list(APPEND SRC_FILES
		"os/macosx/sandbox.c"
	)
endif(APPLE)

if(OPENBSD)
	list(APPEND SRC_FILES
		"os/openbsd/sandbox.c"
	)
endif(OPENBSD)

if(LINUX)
	list(APPEND SRC_FILES
		"compat/strlcpy.c"
		"compat/strlcat.c"
		"compat/explicit_bzero.c"
		"os/linux/sandbox.c"
	)
endif(LINUX)

if(LINUX)
	list(APPEND LIB_FILES
		"dl"
	)
endif()

add_executable(git-lfs-fcgi
	${SRC_FILES}
	${BISON_ConfigParser_OUTPUTS} 
	${FLEX_ConfigParser_OUTPUTS}
)

target_include_directories(git-lfs-fcgi PUBLIC
	${INC_DIRS}
)

target_link_libraries(git-lfs-fcgi PUBLIC
	${LIB_FILES}
)

if(NOT OPENSSL_FOUND)
	add_dependencies(git-lfs-fcgi libressl)
endif()

install(TARGETS git-lfs-fcgi RUNTIME DESTINATION sbin)
install(FILES conf/git-lfs-fcgi.conf DESTINATION etc/git-lfs-fcgi)
install(FILES conf/example-repo.conf DESTINATION etc/git-lfs-fcgi/conf.d)

