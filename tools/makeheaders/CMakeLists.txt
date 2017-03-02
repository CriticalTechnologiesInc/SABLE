#set(SABLE_HEADER_FILES ../../include/*.h)
#
#add_custom_command(

set (CMAKE_C_FLAGS "-ansi")

add_executable (makeheaders EXCLUDE_FROM_ALL
  makeheaders.c
  )
