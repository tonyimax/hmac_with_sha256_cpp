cmake_minimum_required(VERSION 3.31)
project(hmac_with_cpp)

set(CMAKE_CXX_STANDARD 20)

#check the compiler host
message(${CMAKE_SYSTEM})
message(${CMAKE_SYSTEM_NAME})
if (${CMAKE_HOST_LINUX})
    message("===>the cmake check host is Linux")
endif ()
if(${CMAKE_HOST_APPLE})
    message("===>the cmake check host is Apple")
    include_directories( /usr/local/opt/openssl@3/include/)
    link_directories( /usr/local/opt/openssl@3/lib)
endif ()

add_executable(hmac_with_cpp main.cpp)

target_link_libraries(
        hmac_with_cpp
        ssl
        crypto
)
