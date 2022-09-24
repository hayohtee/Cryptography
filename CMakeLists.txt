cmake_minimum_required(VERSION 3.0.0)
project(Cryptography VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CTest)
enable_testing()

add_executable(Cryptography src/main.c)
target_link_libraries(Cryptography PRIVATE -lm)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
