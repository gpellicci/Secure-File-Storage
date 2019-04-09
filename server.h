#include <signal.h>
#include <iostream>
#include <time.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <string>

//constant definition
#define cmdMaxLen 10
#define filenameMaxLen 255
#define serverPort 9090
#define MAX_CONNECTION 30
#define serverIp "127.0.0.1"

bool prepareSocket(struct sockaddr_in& serverAddr, int& server_sock){

    //Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons( serverPort );

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock == -1){
        perror("Could not create socket. Error");
        return 0;
    }
    //Bind
    if( bind(server_sock,(struct sockaddr *)&serverAddr , sizeof(serverAddr)) < 0){
        //print the error message
        perror("Bind failed. Error");
        return 0;
    }

    int listen_ret = listen(server_sock, MAX_CONNECTION); 
    if(listen_ret == -1){
        perror("Could not listen. Error");
        return 0;
    }   
    printf("All good, listening...\n");
	return 1;
}