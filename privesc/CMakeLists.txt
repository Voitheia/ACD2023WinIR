add_executable(
	privesc
	"privesc.cpp"
)

target_link_libraries(
	privesc
	inc
)

add_dependencies(
	privesc
	loader
)

add_custom_command(
	TARGET privesc POST_BUILD
	COMMAND powershell -ExecutionPolicy Bypass -File ${PROJECT_SOURCE_DIR}/Build-Header.ps1 "-name" "privesc"
	COMMENT "Building privesc header"
)