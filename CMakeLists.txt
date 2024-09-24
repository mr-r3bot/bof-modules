cmake_minimum_required(VERSION 3.28)
project(bof_havoc_cs C)

set(CMAKE_C_STANDARD 23)

add_executable(bof_havoc_cs src/ModuleStomping/module_stomping.c
        include/beacon.h
        include/Structs.h
        src/ComExploit/UACBypassCMSTPLUA.c
        include/Win32Helper.h
        src/MiniStd.c
        include/bofdefs.h
        include/bofdefs.h)
