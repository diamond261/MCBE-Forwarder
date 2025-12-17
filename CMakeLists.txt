cmake_minimum_required(VERSION 3.10)
project(PortForwarder VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 源文件
set(SOURCES
    forwarder.cpp
)

set(HEADERS
    forwarder.hpp
)

# 可执行文件
add_executable(forwarder ${SOURCES} ${HEADERS})

# 平台特定配置
if(WIN32)
    target_link_libraries(forwarder ws2_32)
    target_compile_definitions(forwarder PRIVATE _WIN32_WINNT=0x0601)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(forwarder Threads::Threads)
endif()

# 编译选项
target_compile_options(forwarder PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -O2>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -O2>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
)

# 安装
install(TARGETS forwarder DESTINATION bin)