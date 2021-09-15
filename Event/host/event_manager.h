#ifndef __EVENT_MANAGER_H__
#define __EVENT_MANAGER_H__


int event_manager_run(int sd, struct sockaddr_in address, int addrlen, 
                        int *client_socket, int index);

#endif
