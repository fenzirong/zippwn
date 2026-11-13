cmake_minimum_required(VERSION 3.20)
project(zippwn LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # /utf-8 必须开：源码含中文注释，MSVC 默认按本地代码页解析会破坏语法
    add_compile_options(/utf-8 /O2 /Oi /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS /DNDEBUG)
endif()

set(CORE_SOURCES
    core/src/crypto.cpp
    core/src/zipfmt.cpp
    core/src/engine.cpp
    core/src/attack.cpp
    core/src/backend.cpp
)

add_library(zippwn_core STATIC ${CORE_SOURCES})
target_include_directories(zippwn_core PUBLIC core/include)

# C ABI DLL（给 GUI / 其它语言用）
add_library(zippwn SHARED core/src/capi.cpp)
target_link_libraries(zippwn PRIVATE zippwn_core)
set_target_properties(zippwn PROPERTIES OUTPUT_NAME "zippwn")

# 命令行
add_executable(zippwn_cli cli/main.cpp)
target_link_libraries(zippwn_cli PRIVATE zippwn_core)
set_target_properties(zippwn_cli PROPERTIES OUTPUT_NAME "zippwn")

if(MSVC)
    # 多线程运行时
    set_property(TARGET zippwn_core zippwn zippwn_cli PROPERTY
                 MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()
