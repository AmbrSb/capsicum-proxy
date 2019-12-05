set(workdir "${CMAKE_BINARY_DIR}/glog-download")

configure_file("${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt.in"
               "${workdir}/CMakeLists.txt")

execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                RESULT_VARIABLE error
                WORKING_DIRECTORY "${workdir}")
if(error)
  message(FATAL_ERROR "CMake step for ${PROJECT_NAME} failed: ${error}")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} --build .
                RESULT_VARIABLE error
                WORKING_DIRECTORY "${workdir}")
if(error)
  message(FATAL_ERROR "Build step for ${PROJECT_NAME} failed: ${error}")
endif()

set(UNWIND_LIBRARY FALSE)
set(HAVE_PWD_H FALSE)

add_subdirectory("${CMAKE_BINARY_DIR}/glog-src"
                 "${CMAKE_BINARY_DIR}/glog-build" EXCLUDE_FROM_ALL)
