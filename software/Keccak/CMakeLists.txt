set(libSrcs KeccakF-1600-reference.c KeccakF-1600-interface.h)

#if (UNIX)
#    set(libSrcs ${libSrcs} .c)
#else (UNIX)
#    set(libSrcs ${libSrcs} wintool.c)
#endif (UNIX)

add_library(keccak1600 ${libSrcs})
install(TARGETS keccak1600 DESTINATION lib)
