cmake_minimum_required(VERSION 3.0.0)
project(fhe_test VERSION 0.1.0 LANGUAGES CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CTest)
include(CMakePrintHelpers)
enable_testing()

add_executable(fhe_test main.cpp ckks_example.cpp calculators/seal_calc.cpp)

# Get FHE libs
find_package(SEAL PATHS "SEAL/build" NO_DEFAULT_PATH REQUIRED)

find_library(HEAAN libHEAAN.a PATHS "HEAAN/HEAAN/lib" NO_DEFAULT_PATH REQUIRED)
# HEAAN depends on ntl, gmp, libmath, and pthread

find_package(helib PATHS "HElib/build/helib_install" NO_DEFAULT_PATH REQUIRED)

#target_include_directories(fhe_test PRIVATE "HElib/build/lib/src" "HElib/include" ) # add lib header files
target_link_libraries(fhe_test SEAL::seal ${HEAAN} helib ntl gmp m pthread) # link the libs

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
