include_directories(${CMAKE_SOURCE_DIR}/Keccak)
include_directories(${CMAKE_SOURCE_DIR}/libinfnoise)

set(infnoiseCliSrcs infnoise.c daemon.c)

add_executable(infnoise-cli ${infnoiseCliSrcs})

target_link_libraries(infnoise-cli infnoise)

install(TARGETS infnoise-cli DESTINATION bin)
