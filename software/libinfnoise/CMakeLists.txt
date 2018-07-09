include_directories(${CMAKE_SOURCE_DIR}/Keccak)

set(libSrcs libinfnoise.c libinfnoise.h libinfnoise_private.h healthcheck.c ../Keccak/libkeccak1600.a)

#if (UNIX)
#    set(libSrcs ${libSrcs} .c)
#else (UNIX)
#    set(libSrcs ${libSrcs} wintool.c)
#endif (UNIX)

add_library(infnoise SHARED ${libSrcs})
install(TARGETS infnoise DESTINATION lib)
