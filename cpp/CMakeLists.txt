
cmake_minimum_required(VERSION 3.4.1)



add_library(
        vergil

        SHARED

        native-lib.cpp
        mem.cpp
        str_utils.cpp
        utils.cpp
        sm4.cpp

        confhandle.cpp
        mdbase.cpp
        got.cpp
        func.cpp
        sec.cpp
        sys.cpp
        anti_hook.cpp
        )



find_library(
        log-lib

        log )



add_library( ape   SHARED    IMPORTED )
add_library( sm4   SHARED    IMPORTED )
set_target_properties(
        ape
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/${ANDROID_ABI}/libape.so)
set_target_properties(
        sm4
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/${ANDROID_ABI}/libsm4.so)


target_link_libraries(
        vergil
        ape
        sm4
        ${log-lib} )
