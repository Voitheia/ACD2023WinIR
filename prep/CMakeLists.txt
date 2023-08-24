add_executable(
	prep
	"prep.cpp"
)

SET_TARGET_PROPERTIES(prep PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")