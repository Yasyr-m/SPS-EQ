cmake_minimum_required(VERSION 3.10)
project(sps_eq)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add libff include directories
include_directories(/usr/local/include)

# Add executable
add_executable(sps_eq main.cpp sps_eq.cpp)

# Link against libff, gmp, and sodium
find_library(GMP_LIB gmp)
find_library(SODIUM_LIB sodium)
target_link_libraries(sps_eq PRIVATE ff ${GMP_LIB} ${SODIUM_LIB}) 