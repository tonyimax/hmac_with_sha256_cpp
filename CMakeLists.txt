cmake_minimum_required(VERSION 3.31)
project(hmac_with_cpp)

set(CMAKE_CXX_STANDARD 20)
include_directories( /usr/local/opt/openssl@3/include/)
link_directories( /usr/local/opt/openssl@3/lib)

add_executable(hmac_with_cpp main.cpp)

target_link_libraries(
        hmac_with_cpp
        ssl
        crypto
)
