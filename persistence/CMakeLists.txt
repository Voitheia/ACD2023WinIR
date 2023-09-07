add_executable(
	persistence
	"persistence.cpp"
)

target_link_libraries(
	persistence
	inc
)

add_custom_command(
	TARGET persistence POST_BUILD
	COMMAND powershell -ExecutionPolicy Bypass -File ${PROJECT_SOURCE_DIR}/Build-Header.ps1 "-name" "persistence"
	COMMENT "Building persistence header"
)