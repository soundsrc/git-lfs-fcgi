solution "gif-lfs-server"
	configurations { "Debug", "Release" }
	configuration "Debug"
		flags { "ExtraWarnings", "Symbols" }
	configuration "Release"
		flags { "ExtraWarnings", "OptimizeSpeed" }

	project "mongoose"
		kind "StaticLib"
		language "C"
		files {
			"external/mongoose/mongoose.c",
			"external/mongoose/mongoose.h"
		}

	project "json-c"
		kind "StaticLib"
		language "C"
		files {
			"external/json-c/arraylist.c",
			"external/json-c/debug.c",
			"external/json-c/json_c_version.c",
			"external/json-c/json_object.c",
			"external/json-c/json_object_iterator.c",
			"external/json-c/json_tokener.c",
			"external/json-c/json_util.c",
			"external/json-c/linkhash.c",
			"external/json-c/printbuf.c",
			"external/json-c/random_seed.c",
			"external/json-c/arraylist.h",
			"external/json-c/bits.h",
			"external/json-c/debug.h",
			"external/json-c/json.h",
			"external/json-c/json_config.h",
			"external/json-c/json_c_version.h",
			"external/json-c/json_inttypes.h",
			"external/json-c/json_object.h",
			"external/json-c/json_object_iterator.h",
			"external/json-c/json_object_private.h",
			"external/json-c/json_tokener.h",
			"external/json-c/json_util.h",
			"external/json-c/linkhash.h",
			"external/json-c/printbuf.h",
			"external/json-c/random_seed.h"
		}

	project "gif-lfs-server-standalone"
		kind "ConsoleApp"
		language "C"
		includedirs { 
			"external/json-c",
			"external/mongoose",
			"/usr/local/include",
		}
		libdirs { "/usr/local/lib" }
		files { 
			"*.c",
			"*.h",
			"compat/*.h"
		}
		if not os.is("bsd") and not os.is("macosx") then
			files { 
				"compat/*.cpp", 
				"compat/*.c",
			}
		end
		excludes {
			"fcgi_main.c"
		}
		links { "mongoose", "json-c" }
