# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.27

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/hp/project/my_tcp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/hp/project/my_tcp/build

# Include any dependencies generated for this target.
include src/xnet_app/CMakeFiles/xnet_app.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/xnet_app/CMakeFiles/xnet_app.dir/compiler_depend.make

# Include the progress variables for this target.
include src/xnet_app/CMakeFiles/xnet_app.dir/progress.make

# Include the compile flags for this target's objects.
include src/xnet_app/CMakeFiles/xnet_app.dir/flags.make

src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.o: src/xnet_app/CMakeFiles/xnet_app.dir/flags.make
src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.o: /home/hp/project/my_tcp/src/xnet_app/port_pcap.c
src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.o: src/xnet_app/CMakeFiles/xnet_app.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/hp/project/my_tcp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.o"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.o -MF CMakeFiles/xnet_app.dir/port_pcap.c.o.d -o CMakeFiles/xnet_app.dir/port_pcap.c.o -c /home/hp/project/my_tcp/src/xnet_app/port_pcap.c

src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/xnet_app.dir/port_pcap.c.i"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hp/project/my_tcp/src/xnet_app/port_pcap.c > CMakeFiles/xnet_app.dir/port_pcap.c.i

src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/xnet_app.dir/port_pcap.c.s"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hp/project/my_tcp/src/xnet_app/port_pcap.c -o CMakeFiles/xnet_app.dir/port_pcap.c.s

src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.o: src/xnet_app/CMakeFiles/xnet_app.dir/flags.make
src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.o: /home/hp/project/my_tcp/src/xnet_app/xserver_datetime.c
src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.o: src/xnet_app/CMakeFiles/xnet_app.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/hp/project/my_tcp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.o"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.o -MF CMakeFiles/xnet_app.dir/xserver_datetime.c.o.d -o CMakeFiles/xnet_app.dir/xserver_datetime.c.o -c /home/hp/project/my_tcp/src/xnet_app/xserver_datetime.c

src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/xnet_app.dir/xserver_datetime.c.i"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hp/project/my_tcp/src/xnet_app/xserver_datetime.c > CMakeFiles/xnet_app.dir/xserver_datetime.c.i

src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/xnet_app.dir/xserver_datetime.c.s"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hp/project/my_tcp/src/xnet_app/xserver_datetime.c -o CMakeFiles/xnet_app.dir/xserver_datetime.c.s

src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.o: src/xnet_app/CMakeFiles/xnet_app.dir/flags.make
src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.o: /home/hp/project/my_tcp/src/xnet_app/xserver_http.c
src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.o: src/xnet_app/CMakeFiles/xnet_app.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/hp/project/my_tcp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.o"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.o -MF CMakeFiles/xnet_app.dir/xserver_http.c.o.d -o CMakeFiles/xnet_app.dir/xserver_http.c.o -c /home/hp/project/my_tcp/src/xnet_app/xserver_http.c

src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/xnet_app.dir/xserver_http.c.i"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/hp/project/my_tcp/src/xnet_app/xserver_http.c > CMakeFiles/xnet_app.dir/xserver_http.c.i

src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/xnet_app.dir/xserver_http.c.s"
	cd /home/hp/project/my_tcp/build/src/xnet_app && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/hp/project/my_tcp/src/xnet_app/xserver_http.c -o CMakeFiles/xnet_app.dir/xserver_http.c.s

# Object files for target xnet_app
xnet_app_OBJECTS = \
"CMakeFiles/xnet_app.dir/port_pcap.c.o" \
"CMakeFiles/xnet_app.dir/xserver_datetime.c.o" \
"CMakeFiles/xnet_app.dir/xserver_http.c.o"

# External object files for target xnet_app
xnet_app_EXTERNAL_OBJECTS =

src/xnet_app/libxnet_app.a: src/xnet_app/CMakeFiles/xnet_app.dir/port_pcap.c.o
src/xnet_app/libxnet_app.a: src/xnet_app/CMakeFiles/xnet_app.dir/xserver_datetime.c.o
src/xnet_app/libxnet_app.a: src/xnet_app/CMakeFiles/xnet_app.dir/xserver_http.c.o
src/xnet_app/libxnet_app.a: src/xnet_app/CMakeFiles/xnet_app.dir/build.make
src/xnet_app/libxnet_app.a: src/xnet_app/CMakeFiles/xnet_app.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/hp/project/my_tcp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C static library libxnet_app.a"
	cd /home/hp/project/my_tcp/build/src/xnet_app && $(CMAKE_COMMAND) -P CMakeFiles/xnet_app.dir/cmake_clean_target.cmake
	cd /home/hp/project/my_tcp/build/src/xnet_app && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/xnet_app.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/xnet_app/CMakeFiles/xnet_app.dir/build: src/xnet_app/libxnet_app.a
.PHONY : src/xnet_app/CMakeFiles/xnet_app.dir/build

src/xnet_app/CMakeFiles/xnet_app.dir/clean:
	cd /home/hp/project/my_tcp/build/src/xnet_app && $(CMAKE_COMMAND) -P CMakeFiles/xnet_app.dir/cmake_clean.cmake
.PHONY : src/xnet_app/CMakeFiles/xnet_app.dir/clean

src/xnet_app/CMakeFiles/xnet_app.dir/depend:
	cd /home/hp/project/my_tcp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hp/project/my_tcp /home/hp/project/my_tcp/src/xnet_app /home/hp/project/my_tcp/build /home/hp/project/my_tcp/build/src/xnet_app /home/hp/project/my_tcp/build/src/xnet_app/CMakeFiles/xnet_app.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/xnet_app/CMakeFiles/xnet_app.dir/depend
