add_executable(
	prep
	"prep.cpp"
	"../include/logger.cpp"
)

SET_TARGET_PROPERTIES(prep PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")