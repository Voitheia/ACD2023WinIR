add_executable(
	dropper
	"dropper.cpp"
)

target_link_libraries(
	dropper
	inc
)

add_dependencies(
	dropper
	elevate
)

add_custom_command(
	TARGET dropper POST_BUILD
	COMMAND powershell -ExecutionPolicy Bypass -File ${PROJECT_SOURCE_DIR}/Build-Header.ps1 "-name" "dropper"
	COMMENT "Building dropper header"
)