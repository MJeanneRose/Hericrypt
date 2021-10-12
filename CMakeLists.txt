#Set projet
cmake_minimum_required( VERSION 3.16 )

project (HeriCrypt LANGUAGES C VERSION 1.6)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_CONFIGURATION_TYPES RELEASE)

#Configure chemin
set(CMAKE_SOURCE_DIR %{CMAKE_SOURCE_DIR}/src)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(libgcrypt libgcrypt)

include_directories (${GTK3_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS})
add_compile_options(${GTK3_CFLAGS_OTHER})

link_directories(${libgcrypt_LIBRARY_DIRS})
add_compile_options(${libgcrypt_CFLAGS_OTHER})

#Créer des variables avec les fichiers à compiler
file(GLOB SRCS src/*.c ress/ressources.rc)

if(MINGW)
SET(CMAKE_C_FLAGS "-Wall -mwindows -D_WIN32_WINNT=0x0501")
  set(CMAKE_RC_COMPILER_INIT windres)
  ENABLE_LANGUAGE(RC)
  SET(CMAKE_RC_COMPILE_OBJECT
    "<CMAKE_RC_COMPILER> <DEFINES> -i <SOURCE> -o <OBJECT>")
endif(MINGW)


#Compile
add_executable(Hericrypt ${SRCS})
target_link_libraries(Hericrypt ${GTK3_LIBRARIES} ${libgcrypt_LIBRARIES})