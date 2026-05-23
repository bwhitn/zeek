zeek_add_plugin(
    Zeek FileContentSim
    SOURCES ContentSimAnalyzer.cc Plugin.cc ${PROJECT_SOURCE_DIR}/auxil/ssdf/SSDF.cc
            ${PROJECT_SOURCE_DIR}/auxil/highwayhash/c/highwayhash.c
    INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/auxil/ssdf ${PROJECT_SOURCE_DIR}/auxil/highwayhash
    BIFS events.bif)
