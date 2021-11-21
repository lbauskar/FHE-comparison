cmake_minimum_required(VERSION 3.0.0)
project(fhe_test VERSION 0.1.0 LANGUAGES CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CTest)
include(CMakePrintHelpers)
enable_testing()

add_executable(fhe_test main.cpp ckks_example.cpp)

# Get FHE libs
find_package(SEAL PATHS "SEAL/build" NO_DEFAULT_PATH REQUIRED)

find_library(HEAAN libHEAAN.a PATHS "HEAAN/HEAAN/lib" NO_DEFAULT_PATH REQUIRED)
#set_target_properties(HEAAN PROPERTIES LINKER_LANGUAGE CXX)
#target_link_libraries(HEAAN ntl gmp m pthread)
#set(HEAAN_DEPS "ntl gmp m pthread") # HEAAN depends on ntl, gmp, libmath, and pthread

target_link_libraries(fhe_test SEAL::seal ${HEAAN} ntl gmp m pthread) # link the libs

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
