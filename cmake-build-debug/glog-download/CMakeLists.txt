cmake_minimum_required(VERSION 3.10)
project(glog-download NONE)

include(ExternalProject)
ExternalProject_Add(glog
  GIT_REPOSITORY    https://github.com/google/glog.git
  GIT_TAG           ba8a9f6952d04d1403b97df24e6836227751454e  # 2019-05-07
  SOURCE_DIR        "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-src"
  BINARY_DIR        "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
  TEST_COMMAND      ""
)
