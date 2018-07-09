project(InfNoise)

# Get the Github release version
execute_process(
  COMMAND git --no-pager describe --tags --always
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git rev-parse --verify HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get Commit timestamp
execute_process(
  COMMAND git --no-pager show --date=iso-strict --format="%ad" --name-only
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_DATE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_definitions(-DGIT_VERSION=${GIT_VERSION})
add_definitions(-DGIT_COMMIT=${GIT_COMMIT})
add_definitions(-DGIT_DATE=${GIT_DATE})

add_subdirectory(Keccak)
add_subdirectory(libinfnoise)

include_directories(${CMAKE_SOURCE_DIR}/Keccak)
include_directories(${CMAKE_SOURCE_DIR}/libinfnoise)

set(infnoiseCliSrcs infnoise.c daemon.c)
add_executable(infnoise ${infnoiseCliSrcs})

target_link_libraries(infnoise libinfnoise)

install(TARGETS infnoise DESTINATION bin)
