CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(mobileap-agent C)

SET(SRCS src/mobileap_softap.c
	src/mobileap_main.c
	src/mobileap_wifi.c
	src/mobileap_usb.c
	src/mobileap_bluetooth.c
	src/mobileap_handler.c
	src/mobileap_common.c
	src/mobileap_notification.c
	src/mobileap_network.c
	src/mobileap_iptables.c
)

SET(CMAKE_INSTALL_PREFIX /usr)

SET(APP_VENDOR "samsung")
SET(APP_NAME mobileap-agent)
SET(APP_DIR ${CMAKE_INSTALL_PREFIX}/bin)
SET(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

INCLUDE_DIRECTORIES(${INCLUDE_DIR} ${CMAKE_SOURCE_DIR})

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED gio-2.0 gio-unix-2.0 dbus-1 dlog  deviced vconf notification capi-network-connection capi-network-bluetooth appcore-common capi-network-wifi capi-network-wifi-direct alarm-service appsvc libssl)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIE -Wall")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -fPIE")
SET(CMAKE_C_FLAGS_RELEASE "-O2 -fPIE")

FIND_PROGRAM(UNAME NAMES uname)
EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" STREQUAL "arm")
	ADD_DEFINITIONS("-DTARGET")
	MESSAGE("add -DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")
IF(TIZEN_TV)
	ADD_DEFINITIONS(-DTIZEN_TV)
ENDIF(TIZEN_TV)

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DVENDOR=\"${APP_VENDOR}\"")
ADD_DEFINITIONS("-DAPPNAME=\"${APP_NAME}\"")
ADD_DEFINITIONS("-DAPP_DIR=\"${APP_DIR}\"")

IF(TIZEN_WLAN_BOARD_SPRD)
	ADD_DEFINITIONS(-DTIZEN_WLAN_BOARD_SPRD)
ENDIF(TIZEN_WLAN_BOARD_SPRD)

SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed -pie")

ADD_CUSTOM_COMMAND(
	WORKING_DIRECTORY
	OUTPUT ${CMAKE_BINARY_DIR}/tethering-server-stub.c
	COMMAND gdbus-codegen --interface-prefix org.tizen.
			--generate-c-code tethering-server-stub
			--c-generate-object-manager
			--generate-docbook generated-docs
			${INCLUDE_DIR}/tethering-dbus-interface.xml
			COMMENT "Generating GDBus .c/.h")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS} ${CMAKE_BINARY_DIR}/tethering-server-stub.c)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/packaging/org.tizen.tethering.service DESTINATION share/dbus-1/system-services)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tethering_dump.sh DESTINATION /opt/etc/dump.d/module.d/)

