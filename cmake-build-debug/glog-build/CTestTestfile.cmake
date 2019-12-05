# CMake generated Testfile for 
# Source directory: /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-src
# Build directory: /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(demangle "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build/demangle_unittest")
add_test(logging "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build/logging_unittest")
add_test(signalhandler "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build/signalhandler_unittest")
add_test(stacktrace "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build/stacktrace_unittest")
set_tests_properties(stacktrace PROPERTIES  TIMEOUT "30")
add_test(stl_logging "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build/stl_logging_unittest")
add_test(symbolize "/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/glog-build/symbolize_unittest")
