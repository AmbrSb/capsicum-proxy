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
include CMakeFiles/sandbox_clone.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/sandbox_clone.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sandbox_clone.dir/flags.make

CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.o: CMakeFiles/sandbox_clone.dir/flags.make
CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.o: ../tests/libtest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.o -c /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/libtest.cpp

CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/libtest.cpp > CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.i

CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/libtest.cpp -o CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.s

CMakeFiles/sandbox_clone.dir/tests/tests.cpp.o: CMakeFiles/sandbox_clone.dir/flags.make
CMakeFiles/sandbox_clone.dir/tests/tests.cpp.o: ../tests/tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/sandbox_clone.dir/tests/tests.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/sandbox_clone.dir/tests/tests.cpp.o -c /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/tests.cpp

CMakeFiles/sandbox_clone.dir/tests/tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sandbox_clone.dir/tests/tests.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/tests.cpp > CMakeFiles/sandbox_clone.dir/tests/tests.cpp.i

CMakeFiles/sandbox_clone.dir/tests/tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sandbox_clone.dir/tests/tests.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/tests/tests.cpp -o CMakeFiles/sandbox_clone.dir/tests/tests.cpp.s

# Object files for target sandbox_clone
sandbox_clone_OBJECTS = \
"CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.o" \
"CMakeFiles/sandbox_clone.dir/tests/tests.cpp.o"

# External object files for target sandbox_clone
sandbox_clone_EXTERNAL_OBJECTS =

sandbox_clone: CMakeFiles/sandbox_clone.dir/tests/libtest.cpp.o
sandbox_clone: CMakeFiles/sandbox_clone.dir/tests/tests.cpp.o
sandbox_clone: CMakeFiles/sandbox_clone.dir/build.make
sandbox_clone: CMakeFiles/sandbox_clone.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable sandbox_clone"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sandbox_clone.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sandbox_clone.dir/build: sandbox_clone

.PHONY : CMakeFiles/sandbox_clone.dir/build

CMakeFiles/sandbox_clone.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sandbox_clone.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sandbox_clone.dir/clean

CMakeFiles/sandbox_clone.dir/depend:
	cd /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug /home/max/WS/Projects/fbsd-sandboxing/sandbox-clone/cmake-build-debug/CMakeFiles/sandbox_clone.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sandbox_clone.dir/depend
