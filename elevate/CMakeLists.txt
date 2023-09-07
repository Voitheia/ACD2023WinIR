add_executable(
	elevate
	"elevate.cpp"
)

target_link_libraries(
	elevate
	inc
)

add_dependencies(
	elevate
	privesc
)

add_custom_command(
	TARGET elevate POST_BUILD
	COMMAND powershell -ExecutionPolicy Bypass -File ${PROJECT_SOURCE_DIR}/Build-Header.ps1 "-name" "elevate"
	COMMENT "Building elevate header"
)