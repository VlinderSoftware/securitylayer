cmake_minimum_required(VERSION 3.1)
project(secureauthentication VERSION 1.0 LANGUAGES CXX)
enable_testing()

include (cmake/inc/Findsodium.cmake)

add_subdirectory(exceptions)

set(CMAKE_CXX_STANDARD 14)

include(FindThreads)
find_package(Boost REQUIRED COMPONENTS system)
include_directories(${Boost_INCLUDE_DIRS})

include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-psabi")

set(LESS_GENERATOR_SRC
	less.cpp
	)
add_executable(less ${LESS_GENERATOR_SRC})
target_link_libraries(less sodium)

set(LIBLAYER_SRC
	exceptions.cpp
	master.cpp
	outstation.cpp
	securitylayer.cpp
	sessionbuilder.cpp
	)

add_library(secureauthentication SHARED
	${LIBLAYER_SRC}
	)
target_link_libraries(secureauthentication exceptions sodium Boost::system Threads::Threads)
set_target_properties(secureauthentication PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(secureauthentication PROPERTIES SOVERSION 1)
set(LAYER_PUBLIC_HEADERS
	config.hpp
	exceptions.hpp
	master.hpp
	messages.hpp
	messages/error.hpp
	messages/keystatus.hpp
	messages/requestsessioninitiation.hpp
	messages/sessionstartrequest.hpp
	messages/sessionstartresponse.hpp
	messages/setsessionkeys.hpp
	outstation.hpp
	securitylayer.hpp
	sessionbuilder.hpp
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
add_test(test_libsecureauthentication test_libsecureauthentication)
