cmake_minimum_required(VERSION 3.5)

project(libkeccak1600 VERSION 0.1)
set(libSrcs KeccakF-1600-reference.c KeccakF-1600-interface.h)

#if (UNIX)
#    set(libSrcs ${libSrcs} .c)
#else (UNIX)
#    set(libSrcs ${libSrcs} wintool.c)
#endif (UNIX)

add_library(keccak1600 STATIC ${libSrcs})
install(TARGETS keccak1600 DESTINATION lib)
