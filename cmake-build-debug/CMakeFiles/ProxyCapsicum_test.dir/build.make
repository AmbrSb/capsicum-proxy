# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ProxyCapsicum_test.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ProxyCapsicum_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ProxyCapsicum_test.dir/flags.make

CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.o: CMakeFiles/ProxyCapsicum_test.dir/flags.make
CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.o: ../tests/tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.o -c /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/tests.cpp

CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/tests.cpp > CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.i

CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/tests.cpp -o CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.s

# Object files for target ProxyCapsicum_test
ProxyCapsicum_test_OBJECTS = \
"CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.o"

# External object files for target ProxyCapsicum_test
ProxyCapsicum_test_EXTERNAL_OBJECTS =

ProxyCapsicum_test: CMakeFiles/ProxyCapsicum_test.dir/tests/tests.cpp.o
ProxyCapsicum_test: CMakeFiles/ProxyCapsicum_test.dir/build.make
ProxyCapsicum_test: glog-build/libglogd.a
ProxyCapsicum_test: lib/libgtest_maind.a
ProxyCapsicum_test: /usr/local/lib/libgflags.a
ProxyCapsicum_test: lib/libgtestd.a
ProxyCapsicum_test: CMakeFiles/ProxyCapsicum_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ProxyCapsicum_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ProxyCapsicum_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ProxyCapsicum_test.dir/build: ProxyCapsicum_test

.PHONY : CMakeFiles/ProxyCapsicum_test.dir/build

CMakeFiles/ProxyCapsicum_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ProxyCapsicum_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ProxyCapsicum_test.dir/clean

CMakeFiles/ProxyCapsicum_test.dir/depend:
	cd /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles/ProxyCapsicum_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ProxyCapsicum_test.dir/depend
