# Doxygen support for scsl.

find_package(Doxygen)
if (${DOXYGEN_FOUND})
	# prefer scdocs for manpages.
	set(DOXYGEN_GENERATE_MAN YES)
	set(DOXYGEN_GENERATE_LATEX YES)
	set(DOXYGEN_EXTRACT_ALL YES)
	set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
	set(DOXYGEN_EXCLUDE_PATTERNS "test_*" "*.cc" )
	message(STATUS "Doxygen found, building docs.")

	doxygen_add_docs(${PROJECT_NAME}_docs
		${HEADER_FILES}
		ALL
		USE_STAMP_FILE)

	add_custom_target(deploy-docs
			COMMAND rsync --delete-after --progress -auvz ${CMAKE_CURRENT_BINARY_DIR}/html/* docs.shimmering-clarity.net:sites/cc/${PROJECT_NAME}/
			DEPENDS emsha_docs
	)

	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
		${CMAKE_CURRENT_BINARY_DIR}/latex
		DESTINATION share/doc/${PROJECT_NAME}/doxygen)
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/man
		DESTINATION share)
endif ()

