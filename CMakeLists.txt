cmake_minimum_required ( VERSION 3.4.3 )
project ( dpx CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

#file(GLOB SOURCES dpx.cc tpkt_paf.cc tpkt.cc)
file(GLOB SOURCES "src/*" "src/asn1_iso8823/*" "src/asn1_mms/*" "src/asn1_acse/*")

add_library (
    dpx MODULE
    ${SOURCES}
)

if ( APPLE )
    set_target_properties (
        dpx
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    dpx
    PROPERTIES
        PREFIX ""
)


target_include_directories (
    dpx PUBLIC
    ${SNORT3_INCLUDE_DIRS}
    PUBLIC include
    PUBLIC include/asn1_iso8823
    PUBLIC include/asn1_mms
    PUBLIC include/asn1_acse
)

install (
    TARGETS dpx
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/inspectors"
)
