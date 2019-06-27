cmake_minimum_required(VERSION 3.1)
project(secureauthentication VERSION 1.0 LANGUAGES C CXX)
enable_testing()

include (cmake/inc/Findsodium.cmake)

option(SA_COVERAGE "Enable code coverage" OFF)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)
if (SA_COVERAGE)
    include(CodeCoverage)
endif()

add_subdirectory(exceptions)

set(CMAKE_CXX_STANDARD 14)

include(FindThreads)
find_package(Boost REQUIRED COMPONENTS date_time regex system)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${BOOST_LIBRARYDIR})

include(GNUInstallDirs)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-psabi -include \"${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp\"")
endif()
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_WIN32_WINNT=0x0601 /FI\"${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp\"")
#	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4061 /wd4100 /wd4191 /wd4242 /wd4266 /wd4355 /wd4365 /wd4464 /wd4514 /wd4548 /wd4571 /wd4574 /wd4619 /wd4625 /wd4626 /wd4668 /wd4710 /wd4820 /wd4826 /wd5026 /wd5027 /wd5031 -D_WIN32_WINNT=0x0601")
endif()

set(LESS_GENERATOR_SRC
	less.cpp
	)
add_executable(less ${LESS_GENERATOR_SRC})
target_link_libraries(less sodium)

set(LIBLAYER_SRC
	details/randomnumbergenerator.cpp
	exceptions.cpp
	master.cpp
	outstation.cpp
	securitylayer.cpp
	sessionbuilder.cpp
	)

add_library(secureauthentication SHARED
	${LIBLAYER_SRC}
	)
target_link_libraries(secureauthentication exceptions sodium Boost::system Boost::date_time Boost::regex Threads::Threads)
set_target_properties(secureauthentication PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
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
	profile.hpp
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

if (SA_COVERAGE)
	append_coverage_compiler_flags()
	setup_target_for_coverage_lcov(NAME secureauthentication_coverage EXECUTABLE test_libsecureauthentication DEPENDENCIES test_libsecureauthentication)
endif()
