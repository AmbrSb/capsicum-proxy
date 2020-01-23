cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(ProxyCapsicum VERSION 0.0.1 DESCRIPTION "Capsicum Proxy")

set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

include(InstallRequiredSystemLibraries)
include(GNUInstallDirs)
include(CTest)

find_package(Git)
find_package(Threads)

find_program(MAKE_EXE NAMES make)
find_program(GIT_EXE NAMES git)

option(UseCapsicum "Enable use of capability mode in FreeBSD" ON)

if(UseCapsicum)
	add_definitions(-DProxy_CapabilityMode)
endif()

enable_testing()

add_compile_options(
        -Wall -Wpedantic -fexceptions
        "$<$<CONFIG:Debug>:-O0;-g3;-ggdb>"
        "$<$<CONFIG:Release>:-O2>"
)

if(GIT_FOUND AND NOT EXISTS "${CMAKE_SOURCE_DIR}/.git")
    message(WARNING "Configre Git!")
elseif(GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-list --max-count=1 HEAD
            OUTPUT_VARIABLE GIT_REVISION
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            ERROR_QUIET
    )
    if(NOT ${GIT_REVISION} STREQUAL "")
        string(STRIP ${GIT_REVISION} GIT_REVISION)
    endif()
endif()

add_compile_definitions(
        FORTIFY_SOURCE=2
        "$<$<CONFIG:Debug>:MALLOC_CHECK_=3;_GLIBCXX_DEBUG>"
)

set(GSL_SOURCE_DIR "${CMAKE_BINARY_DIR}/gsl-src")
include_directories(${GSL_SOURCE_DIR}/include)

include_directories(/usr/local/include include)
link_directories(/usr/local/lib)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/deps")
include(Opts)
include(Deps)

add_executable(${PROJECT_NAME}_test
        ${PROJECT_SOURCE_DIR}/tests/tests.cpp
        ${PROJECT_SOURCE_DIR}/include/proxy.hpp
        )
target_link_libraries(${PROJECT_NAME}_test
                      gtest_main
                      dl
                      rt
                      )
add_test(ProxyTest ${PROJECT_NAME}_test)

include(CPack)
