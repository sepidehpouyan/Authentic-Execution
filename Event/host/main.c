#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <errno.h>  

#include <netdb.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/types.h> 

#include <unistd.h>   //close  
#include <arpa/inet.h>    //close 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 

#include "event_manager.h"
#include "networking.h"

#define PORT 1236 
#define SA struct sockaddr
     
#define TRUE   1  
#define FALSE  0  
#define MAX 100000
  
// Driver function 
int main() 
{

    int opt = TRUE;   
    int master_socket, addrlen, new_socket, client_socket[30],  
          max_clients = 30 , activity, i, valread, sd;   
    int max_sd;   
    struct sockaddr_in address;
         
    //set of socket descriptors  
    fd_set readfds; 
     
    //initialise all client_socket[] to 0 so not checked  
    for (i = 0; i < max_clients; i++)   
    {   
        client_socket[i] = 0;   
    } 

    //create a master socket  
    if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)   
    {   
        perror("socket failed");   
        exit(EXIT_FAILURE);   
    }   
     
    //set master socket to allow multiple connections ,  
    //this is just a good habit, it will work without this  
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    }   
   
    bzero(&address, sizeof(address)); 
    
    //type of socket created  
    address.sin_family = AF_INET;   
    address.sin_addr.s_addr = INADDR_ANY;   
    address.sin_port = htons(PORT);  

    //printf(" ip is : %s , port : %d\n",
                     //inet_ntoa(address.sin_addr) , ntohs(address.sin_port));  
         
    //bind the socket to localhost port 1236  
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)   
    {   
        perror("bind failed");   
        exit(EXIT_FAILURE);   
    }   
    //printf("Listener on port %d \n", PORT);   
         
    //try to specify maximum of 3 pending connections for the master socket  
    if (listen(master_socket, 3) < 0)   
    {   
        perror("listen");   
        exit(EXIT_FAILURE);   
    }   
         
    //accept the incoming connection  
    addrlen = sizeof(address);   
    puts("Waiting for connections ...");

    while(TRUE)   
    {   
        //clear the socket set  
        FD_ZERO(&readfds);   
     
        //add master socket to set  
        FD_SET(master_socket, &readfds);   
        max_sd = master_socket;   
             
        //add child sockets to set  
        for ( i = 0 ; i < max_clients ; i++)   
        {   
            //socket descriptor  
            sd = client_socket[i];   
                 
            //if valid socket descriptor then add to read list  
            if(sd > 0)   
                FD_SET( sd , &readfds);   
                 
            //highest file descriptor number, need it for the select function  
            if(sd > max_sd)   
                max_sd = sd;   
        }   
     
        //wait for an activity on one of the sockets , timeout is NULL ,  
        //so wait indefinitely  
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);   
       
        if ((activity < 0) && (errno!=EINTR))   
        {   
            printf("select error");   
        }   
             
        //If something happened on the master socket ,  
        //then its an incoming connection  
        if (FD_ISSET(master_socket, &readfds)) {  
             
            if ((new_socket = accept(master_socket,  
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)   
            {   
                perror("accept");   
                exit(EXIT_FAILURE);   
            } 
            //printf("accept new socket:%d\n", new_socket);  
             
            //inform user of socket number - used in send and receive commands  
            //printf("New connection , socket fd is %d , ip is : %s , port : %d\n",
                    //new_socket , inet_ntoa(address.sin_addr) , ntohs(address.sin_port)); 
               
            //add new socket to array of sockets  
            for (i = 0; i < max_clients; i++)   
            {   
                //if position is empty  
                if( client_socket[i] == 0 )   
                {   
                    client_socket[i] = new_socket;   
                    //printf("Adding new socket %d to list of sockets as %d\n" , new_socket , i);    
                    break;   
                }   
            }   
        }   
             
        //else its some IO operation on some other socket 
        for (i = 0; i < max_clients; i++)   
        {   
            sd = client_socket[i];   
                 
            if (FD_ISSET(sd , &readfds))   
            {
                int res = event_manager_run(sd, address, addrlen, client_socket, i);
                
            }
        } 
    }  

} 
