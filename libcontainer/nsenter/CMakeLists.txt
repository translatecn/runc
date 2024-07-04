cmake_minimum_required(VERSION 3.28)
project(nsenter C)

set(CMAKE_C_STANDARD 11)

add_executable(nsenter
        nsexec.c
        escape.c
        namespace.h
        cloned_binary.c
        debug/clone.c
        debug/spilt.c
        debug/ns.c
)
