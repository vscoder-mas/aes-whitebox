cmake_minimum_required(VERSION 3.10.2)

PROJECT(whitebox.out)
set(CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(.)
ADD_EXECUTABLE(${PROJECT_NAME}
    aes_whitebox_prodreqx.cc
    aes_whitebox_prodrspx.cc
    aes_whitebox_testreqx.cc
    aes_whitebox_testrspx.cc
    main.cc
)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} m z)


