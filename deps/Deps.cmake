if(${PROJECT_NAME}_USE_GLOG)
    include(deps/glog/Download.cmake)
else()
    message("GLOG is disabled")
endif()

if(${PROJECT_NAME}_USE_GSL)
    include(deps/gsl/Download.cmake)
else()
    message("GSL is disabled")
endif()

if(${PROJECT_NAME}_USE_GOOGLETEST)
    include(deps/googletest/Download.cmake)
endif()

