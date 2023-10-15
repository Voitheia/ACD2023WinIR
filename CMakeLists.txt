cmake_minimum_required(VERSION 3.26)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project (
	"Windows IR Lab"
	DESCRIPTION "UMBC Active Cyber Defense 2023 Windows LR Lab"
)

#add_subdirectory("prep")
#add_subdirectory("dropper")
#add_subdirectory("elevate")
add_subdirectory("privesc")
add_subdirectory("loader")
add_subdirectory("persistence")
add_subdirectory("listener")
add_subdirectory("include")
add_subdirectory("decode")