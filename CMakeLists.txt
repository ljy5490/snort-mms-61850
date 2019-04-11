cmake_minimum_required ( VERSION 3.4.3 )
project ( iec61850 CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

file(GLOB SOURCES "src/*" "src/asn1_iso8823/*" "src/asn1_mms/*" "src/asn1_acse/*")

add_library (
    iec61850 MODULE
    ${SOURCES}
)

if ( APPLE )
    set_target_properties (
        iec61850
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    iec61850
    PROPERTIES
        PREFIX ""
)


target_include_directories (
    iec61850 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
    PUBLIC include
    PUBLIC include/asn1_iso8823
    PUBLIC include/asn1_mms
    PUBLIC include/asn1_acse
)

install (
    TARGETS iec61850
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/inspectors"
)
