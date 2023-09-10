add_library(
	listener
	SHARED
	"listener.cpp"
)

target_link_libraries(
	listener
	inc
)

add_custom_command(
	TARGET listener POST_BUILD
	COMMAND powershell -ExecutionPolicy Bypass -File ${PROJECT_SOURCE_DIR}/Build-Header.ps1 "-name" "listener"
	COMMENT "Building listener header"
)