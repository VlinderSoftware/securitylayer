cmake_minimum_required(VERSION 3.1)
project(secureauthentication VERSION 1.0 LANGUAGES CXX)

add_subdirectory(exceptions)

set(CMAKE_CXX_STANDARD 14)

find_package(Boost)
include_directories(${Boost_INCLUDE_DIRS})

include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-psabi")

set(LIBLAYER_SRC
	securitylayer.cpp
	)

add_library(secureauthentication SHARED
	${LIBLAYER_SRC}
	)
target_link_libraries(secureauthentication exceptions)
set_target_properties(secureauthentication PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(secureauthentication PROPERTIES SOVERSION 1)
set(LAYER_PUBLIC_HEADERS
	applicationlayer.hpp
	securitylayer.hpp
	transportfunction.hpp
	)
#set(LAYER_PUBLIC_DETAILS_HEADERS
#	)
set_target_properties(secureauthentication PROPERTIES
	PUBLIC_HEADER "${FRAM_PUBLIC_HEADERS}"
	)
install(TARGETS secureauthentication
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	)
#install(FILES ${LAYER_PUBLIC_DETAILS_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/details)

file(GLOB TEST_LIBLAYER_SOURCES tests/*.cpp)
add_executable(test_libsecureauthentication
	${TEST_LIBLAYER_SOURCES}
	)
target_link_libraries(test_libsecureauthentication secureauthentication)

