add_executable(
	prep
	"prep.cpp"
)

target_link_libraries(
	prep
	inc
)

add_dependencies(
	prep
	dropper
)

SET_TARGET_PROPERTIES(prep PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")