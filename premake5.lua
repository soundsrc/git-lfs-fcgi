solution "gif-lfs-fcgi"
	configurations { "Debug", "Release" }
	configuration "Debug"
		flags { "ExtraWarnings", "Symbols" }
	configuration "Release"
		flags { "ExtraWarnings", "OptimizeSpeed" }

	project "gif-lfs-fcgi"
		kind "ConsoleApp"
		language "C"
		includedirs { 
			"/usr/local/include",
		}
		libdirs { "/usr/local/lib" }
		files { 
			"*.c",
			"*.h"
		}
		if not os.is("bsd") and not os.is("macosx") then
			files { 
				"common/bsdcompat/*.cpp", 
				"common/bsdcompat/*.c",
				"common/bsdcompat/*.h"
			}
		end
		links { "fcgi", "ssl", "crypto" }
