cmake_minimum_required(VERSION 3.22)
project(emsha
	VERSION 1.1.1
	LANGUAGES CXX 
	DESCRIPTION "A compact HMAC-SHA-256 C++11 library.")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SET_EMSHA_NO_HEXSTRING OFF CACHE BOOL
	"Don't include support for hex strings.")
if (SET_EMSHA_NO_HEXSTRING)
	add_definitions(EMSHA_NO_HEXSTRING)
endif ()
set(SET_EMSHA_NO_HEXLUT OFF CACHE BOOL
	"Don't use a LUT for hex strings (saves ~256B of memory).")
if (SET_EMSHA_NO_HEXLUT)
	add_definitions("-DEMSHA_NO_HEXLUT")
endif ()

set(SET_EMSHA_NO_SELFTEST OFF CACHE BOOL
	"Disable the internal self-tests.")
if (SET_EMSHA_NO_SELFTEST)
	add_definitions("-DEMSHA_NO_SELFTEST")
endif ()


include(CTest)
enable_testing()

# compile options:                    
#   -Wall                   Default to all errors.
#   -Wextra                 And a few extra.
#   -Werror                 And require them to be fixed to build.
#   -Wno-unused-function    This is a library. Not every function is used here.
#   -Wno-unused-parameter   Some functions have parameters defined for compatibility,
#                           and aren't used in the implementation.
add_compile_options(                   
        "-static"               
        "-Wall"
        "-Wextra"                  
        "-Werror"                   
        "-Wno-unused-function"
        "-Wno-unused-parameter"
        "-g"                                     
        "$<$<CONFIG:RELEASE>:-O2>"         
)                                       
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options("-stdlib=libc++")
else ()                              
    # nothing special for gcc at the moment
endif ()

### Set up the build ###
set(HEADERS
        include/emsha/emsha.h
        include/emsha/sha256.h
        include/emsha/hmac.h
        include/emsha/internal.h)
set(SOURCES src/emsha.cc src/sha256.cc src/hmac.cc)

include_directories(include)

### Build products ###

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

### TESTS ###

set(TEST_SOURCES test/test_utils.cc)
macro(generate_test name)
	add_executable(${name} test/${name}.cc ${TEST_SOURCES} ${ARGN})
	target_link_libraries(${name} ${PROJECT_NAME})
	target_include_directories(${name} PRIVATE test)
	add_test(${name} ${name})
endmacro()

generate_test(test_${PROJECT_NAME})
generate_test(test_hmac)
generate_test(test_mem)
generate_test(test_sha256)

include(cmake/docs.cmake)
include(cmake/install.cmake)
include(cmake/packaging.cmake)
