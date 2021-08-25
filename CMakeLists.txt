# Set the minimum version of CMake that can be used
cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 14)

# Set the project name
project(DPITunnel-cli)

# Add dependencies
add_subdirectory(RawSocket)
add_subdirectory(cpp-httplib)
add_subdirectory(dnslib)
add_subdirectory(libnl)

# Add an executable
add_executable(DPITunnel-cli-exec
		autoconf.cpp
		desync.cpp
		dns.cpp
		dpitunnel-cli.cpp
		netiface.cpp
		packet.cpp
		profiles.cpp
		socket.cpp
		ssl.cpp
		utils.cpp
)

# Set the directories that should be included in the build command for this target
target_include_directories(DPITunnel-cli-exec
		PRIVATE
		${PROJECT_SOURCE_DIR}/include
		${PROJECT_SOURCE_DIR}/RawSocket/include
		${PROJECT_SOURCE_DIR}/cpp-httplib/include
		${PROJECT_SOURCE_DIR}/dnslib/include
		${PROJECT_SOURCE_DIR}/libnl/include
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(DPITunnel-cli-exec
		RawSocket
		cpp-httplib
		dnslib
		libnl
		Threads::Threads
		OpenSSL::SSL
)
