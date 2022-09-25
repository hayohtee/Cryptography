cmake_minimum_required(VERSION 3.0.0)
project(Cryptography VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CTest)
enable_testing()

add_executable(Cryptography src/cipher_test.c src/cipher.c)
target_link_libraries(Cryptography PRIVATE -lm)
target_include_directories(Cryptography PRIVATE "include/")

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
