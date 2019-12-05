# CMake generated Testfile for 
# Source directory: /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone
# Build directory: /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(ProxyTest "ProxyCapsicum_test")
subdirs("glog-build")
subdirs("googletest-build")
