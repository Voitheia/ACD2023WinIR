cmake_minimum_required(VERSION 3.26)

project (
	"Windows IR Lab"
	DESCRIPTION "UMBC Active Cyber Defense 2023 Windows LR Lab"
)

add_subdirectory("prep")
add_subdirectory("dropper")
add_subdirectory("privesc")
add_subdirectory("persistence")
add_subdirectory("listener")