cmake_minimum_required(VERSION 3.28)
project(TestOpTime)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE COMMON_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

# 这里搜索所有的测试文件，后续将每个测试文件各编译为一个可执行文件
set(MAIN_SOURCES
        src/TestGMP.cpp
)

# 设置头文件目录
set(INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/libsh
)

# 设置链接库目录
set(LINK_LIBS
#        ${CMAKE_CURRENT_SOURCE_DIR}/libs/bls12381.a
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/core.a
        gmp
        gmpxx
        benchmark::benchmark      # 加入Google Benchmark库
)

# 设置编译选项，为每个test文件单独编译
foreach(MAIN_SRC ${MAIN_SOURCES})
    get_filename_component(EXE_NAME ${MAIN_SRC} NAME_WE)
    add_executable(${EXE_NAME} ${COMMON_SRC} ${MAIN_SRC})
    target_include_directories(${EXE_NAME} PUBLIC ${INCLUDE_DIRS})
    target_link_libraries(${EXE_NAME} PRIVATE ${LINK_LIBS})
endforeach()

# 寻找必要的依赖项
find_library(GMP gmp REQUIRED)
find_library(GMPXX gmpxx REQUIRED)
find_package(benchmark REQUIRED)   # 查找Google Benchmark库
