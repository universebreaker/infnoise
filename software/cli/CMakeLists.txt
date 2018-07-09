include_directories(${CMAKE_SOURCE_DIR}/Keccak)
include_directories(${CMAKE_SOURCE_DIR}/libinfnoise)

set(infnoiseCliSrcs infnoise.c daemon.c)
add_executable(infnoise ${infnoiseCliSrcs})

target_link_libraries(infnoise libinfnoise)

install(TARGETS infnoise DESTINATION bin)
