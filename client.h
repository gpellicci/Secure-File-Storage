#include <limits>
#include <iostream>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
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
#define serverIp "127.0.0.1"
#define serverPort 9090

using namespace std;


int connectToServer(const char* ip, unsigned int port){
    
    struct sockaddr_in serverAddr;

    //Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(client_sock == -1){
        perror("Could not create socket. Error\n");
        return -1;
    }

    //Connect to remote server
    if (connect(client_sock , (struct sockaddr *)&serverAddr , sizeof(serverAddr)) < 0){
        perror("Connect failed. Error");
        return -1;
    }

    printf("Connection to the server %s:%d successful\n",  inet_ntoa(serverAddr.sin_addr), port);
    return client_sock;
}


void commands_available(){
    cout << "\033[1;33mCOMMANDS\033[0m\n";
    cout << "'list' to have a list of file available on the server\n";  
    cout << "'down filename' to download file filename from the server\n";  
    cout << "'up filename' to upload file filename on the server\n";  
    cout << "'info' to have some information about the protocol\n";  
    cout << "'quit' or 'exit' to terminate the program\n";  
}