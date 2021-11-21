cmake_minimum_required(VERSION 3.0.0)
project(fhe_test VERSION 0.1.0 LANGUAGES CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CTest)
enable_testing()

add_executable(fhe_test main.cpp ckks_example.cpp)

# Get FHE libs
include(./SEAL/build/cmake/SEALConfig.cmake) # Microsoft SEAL
target_link_libraries(fhe_test SEAL::seal)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

