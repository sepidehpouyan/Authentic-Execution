project (optee_example_event C)

add_executable (${PROJECT_NAME}  host/main.c  host/event_manager.c  host/command_handlers.c 
        host/networking.c  host/utils.c  host/enclave_utils.c host/connection.c host/uuid.c)


target_include_directories(${PROJECT_NAME}
			   PRIVATE host
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})


