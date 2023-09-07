add_executable(
	loader
	"loader.cpp"
)

target_link_libraries(
	loader
	inc
)

add_dependencies(
	loader
	persistence
	listener
)

add_custom_command(
	TARGET loader POST_BUILD
	COMMAND powershell -ExecutionPolicy Bypass -File ${PROJECT_SOURCE_DIR}/Build-Header.ps1 "-name" "loader"
	COMMENT "Building loader header"
)