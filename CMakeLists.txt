# Copyright 2019  Ronald Landheer-Cieslak
#
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software 
# distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and 
# limitations under the License. 
cmake_minimum_required(VERSION 3.1)
project(secureauthentication VERSION 1.0 LANGUAGES C CXX)
enable_testing()

if (WIN32)
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /FC")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /FC")
endif()

include(FindOpenSSL)
include_directories(${OPENSSL_INCLUDE_DIR})

option(SA_COVERAGE "Enable code coverage" OFF)
option(SA_PROFILES "Try all profiles" OFF)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)
if (SA_COVERAGE)
    include(CodeCoverage)
endif()

add_subdirectory(exceptions)

set(CMAKE_CXX_STANDARD 14)

include(FindThreads)

set(Boost_USE_STATIC_LIBS       OFF)
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
find_package(Boost REQUIRED COMPONENTS date_time regex system filesystem)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${BOOST_LIBRARYDIR})

include(GNUInstallDirs)

set(LAYER_PUBLIC_HEADERS
	aeadalgorithm.hpp
	config.hpp
	details/icertificatestore.hpp
	exceptions.hpp
	keywrapalgorithm.hpp
	master.hpp
	messages.hpp
	messages/error.hpp
	messages/securemessage.hpp
	messages/sessioninitiation.hpp
	messages/sessionkeychangerequest.hpp
	messages/sessionkeychangeresponse.hpp
	messages/sessionstartrequest.hpp
	messages/sessionstartresponse.hpp
	messages/wrappedkeydata.hpp
	outstation.hpp
	profile.hpp
	securitylayer.hpp
	session.hpp
	sessionbuilder.hpp
	statistics.hpp
	)
#set(LAYER_PUBLIC_DETAILS_HEADERS
#	)
set(LIBLAYER_SRC
	${LAYER_PUBLIC_HEADERS}
	aead.cpp
	aead.hpp
	aeadalgorithm.cpp
	details/aeadhmacadapter.hpp
	details/aesgcm.cpp
	details/aesgcm.hpp
	details/certificate.cpp
	details/certificate.hpp
	details/certificatesignrequest.cpp
	details/certificatesignrequest.hpp
	details/certificatestore.cpp
	details/certificatestore.hpp
	details/distinguishedname.cpp
	details/distinguishedname.hpp
	details/distinguishednameparser.cpp
	details/distinguishednameparser.hpp
	details/ecdh.cpp
	details/ecdh.hpp
	details/ecdhpublickey.cpp
	details/ecdhpublickey.hpp
	details/hmac.cpp
	details/hmac.hpp
	details/hmacaeadadapter.hpp
	details/hmacblake2s.cpp
	details/hmacblake2s.hpp
	details/hmacsha256.cpp
	details/hmacsha256.hpp
	details/hmacsha3256.cpp
	details/hmacsha3256.hpp
	details/hkdf.cpp
	details/hkdf.hpp
	details/iaead.hpp
	details/icertificatestore.cpp
	details/icertificatestore.hpp
	details/ihmac.hpp
	details/ikeywrap.hpp
	details/intermediatebufferadapter.cpp
	details/intermediatebufferadapter.hpp
	details/irandomnumbergenerator.hpp
	details/pbkdf2.cpp
	details/pbkdf2.hpp
	details/privatekey.cpp
	details/privatekey.hpp
	details/publickey.cpp
	details/publickey.hpp
	details/randomnumbergenerator.cpp
	details/randomnumbergenerator.hpp
	details/rfc3394aes256keywrap.cpp
	details/rfc3394aes256keywrap.hpp
	details/seqvalidator.cpp
	details/seqvalidator.hpp
	exceptions.cpp
	hmac.cpp
	hmac.hpp
	master.cpp
	messages/wrappedkeydata.cpp
	outstation.cpp
	securitylayer.cpp
	session.cpp
	sessionbuilder.cpp
	)

add_library(secureauthentication SHARED
	${LIBLAYER_SRC}
	)
target_link_libraries(secureauthentication exceptions OpenSSL::Crypto Boost::system Boost::date_time Boost::regex Threads::Threads)
set_target_properties(secureauthentication PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
set_target_properties(secureauthentication PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(secureauthentication PROPERTIES SOVERSION 1)
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	target_compile_options(secureauthentication PRIVATE -Wno-psabi -include ${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp)
endif()
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	target_compile_options(secureauthentication PRIVATE -D_WIN32_WINNT=0x0601 /FI "${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp" /wd4996)
endif()

set_target_properties(secureauthentication PROPERTIES
	PUBLIC_HEADER "${FRAM_PUBLIC_HEADERS}"
	)
install(TARGETS secureauthentication
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	)
#install(FILES ${LAYER_PUBLIC_DETAILS_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/details)

set(LESS_GENERATOR_SRC
	less.cpp
	)
add_executable(less ${LESS_GENERATOR_SRC})
target_link_libraries(less secureauthentication OpenSSL::Crypto)
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	target_compile_options(less PRIVATE -Wno-psabi -include ${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp)
endif()
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	target_compile_options(less PRIVATE -D_WIN32_WINNT=0x0601 /FI "${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp" /wd4996)
endif()

set(GENCERTS_SRC
	tests/gencerts.cpp
	details/certificate.cpp
	details/certificate.hpp
	details/certificatesignrequest.cpp
	details/certificatesignrequest.hpp
	details/distinguishednameparser.cpp
	details/distinguishednameparser.hpp
	details/ecdhpublickey.cpp
	details/ecdhpublickey.hpp
	details/pbkdf2.cpp
	details/pbkdf2.hpp
	)
add_executable(gencerts ${GENCERTS_SRC})
target_link_libraries(gencerts OpenSSL::Crypto exceptions)
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	target_compile_options(less PRIVATE -Wno-psabi -include ${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp)
endif()
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	target_compile_options(less PRIVATE -D_WIN32_WINNT=0x0601 /FI "${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp" /wd4996)
endif()

file(GLOB TEST_LIBLAYER_SOURCES tests/*.test.cpp)
add_executable(test_libsecureauthentication
	${TEST_LIBLAYER_SOURCES}
	tests/catch.hpp
	tests/deterministicrandomnumbergenerator.cpp
	tests/deterministicrandomnumbergenerator.hpp
	tests/main.cpp
	)
target_link_libraries(test_libsecureauthentication secureauthentication Boost::filesystem)
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	target_compile_options(test_libsecureauthentication PRIVATE -Wno-psabi -include ${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp)
endif()
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	target_compile_options(test_libsecureauthentication PRIVATE -D_WIN32_WINNT=0x0601 /FI "${CMAKE_CURRENT_SOURCE_DIR}/profile.hpp" /wd4996)
endif()
add_test(test_libsecureauthentication test_libsecureauthentication)

if (SA_COVERAGE)
	append_coverage_compiler_flags()
	setup_target_for_coverage_lcov(NAME secureauthentication_coverage EXECUTABLE test_libsecureauthentication DEPENDENCIES test_libsecureauthentication)
endif()

if (SA_PROFILES)
	foreach (prof RANGE 0 15)
		add_library(secureauthentication-${prof} SHARED
			${LIBLAYER_SRC}
			)
		target_link_libraries(secureauthentication-${prof} exceptions OpenSSL::Crypto Boost::system Boost::date_time Boost::regex Threads::Threads)
		set_target_properties(secureauthentication-${prof} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
		set_target_properties(secureauthentication-${prof} PROPERTIES VERSION ${PROJECT_VERSION})
		set_target_properties(secureauthentication-${prof} PROPERTIES SOVERSION 1)
		if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
			target_compile_options(secureauthentication-${prof} PRIVATE -Wno-psabi -include ${CMAKE_CURRENT_SOURCE_DIR}/profile-${prof}.hpp)
		endif()
		if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
			target_compile_options(secureauthentication-${prof} PRIVATE -D_WIN32_WINNT=0x0601 /FI "${CMAKE_CURRENT_SOURCE_DIR}/profile-${prof}.hpp" /wd4996)
		endif()
		add_executable(test_libsecureauthentication-${prof}
			${TEST_LIBLAYER_SOURCES}
			)
		target_link_libraries(test_libsecureauthentication-${prof} secureauthentication-${prof} Boost::filesystem)
		if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
			target_compile_options(test_libsecureauthentication-${prof} PRIVATE -Wno-psabi -include ${CMAKE_CURRENT_SOURCE_DIR}/profile-${prof}.hpp)
		endif()
		if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
			target_compile_options(test_libsecureauthentication-${prof} PRIVATE -D_WIN32_WINNT=0x0601 /FI "${CMAKE_CURRENT_SOURCE_DIR}/profile-${prof}.hpp" /wd4996)
		endif()
		add_test(test_libsecureauthentication-${prof} test_libsecureauthentication-${prof})
	endforeach(prof)
endif()
