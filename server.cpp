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

#include "cryptography.h"
#include "communication.h"

#define MAX_CONNECTION 30
#define cmdMaxLen 10
#define filenameMaxLen 255

using namespace std; 

/*
	TODO funzione a parte che prepara il socket, nel caso aggiungere a un file server.h

bool prepare_socket(struct sockaddr_in& serverAddr, int& serv_sock){

    //Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons( server_port );

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock == -1){
        perror("Could not create socket. Error");
        return false;
    }
    //Bind
    if( bind(server_sock,(struct sockaddr *)&serverAddr , sizeof(serverAddr)) < 0){
        //print the error message
        perror("Bind failed. Error");
        return false;
    }

    listen(server_sock, MAX_CONNECTION);
	return true;
}

*/

int main(){
    //std::string s = "prova.txt";
    //printf("\nSize is %u\n", getFileSize(s));

    struct sockaddr_in serverAddr, client;
    int server_port = 9090;
    int c = sizeof(struct sockaddr_in);
/*
	TODO
	int servr_sock;
	bool r = prepare_socket();
	if(!r){
		cout << "ERRORE!\n";
	}
*/

    //Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons( server_port );

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock == -1){
        perror("Could not create socket. Error");
        return 1;
    }
    //Bind
    if( bind(server_sock,(struct sockaddr *)&serverAddr , sizeof(serverAddr)) < 0){
        //print the error message
        perror("Bind failed. Error");
        return 1;
    }

    listen(server_sock, MAX_CONNECTION);    
    printf("All good, listening...\n");


    while(1){

        int tcp_client = accept(server_sock, (struct sockaddr *)&client, (socklen_t*)&c);
            if (tcp_client < 0){
                cout << "Accept failed";
                return 1;
            }
        printf("Incoming connection from %s:%d -> Accepted\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

        char* buf;

        //get command
        int len = recvCryptoString(tcp_client, buf);
        printf("buf: %s\n", buf);

        if(strcmp(buf, "list") == 0 ){            
            cout << "list\n";
            //generate a file with a list of files (no directories)
            system("ls -p serverDir/ | grep -v / > serverDir/list/list.txt");            
            //add a * to the end of the file (so it's not empty if no file are present)
            system("echo '*' >> serverDir/list/list.txt");
            //send the file containing the list to the client
            sendCryptoFileTo(tcp_client, "serverDir/list/list.txt");
            //remove the file
            system("rm serverDir/list/list.txt");
        }
        else if(strcmp(buf, "up") == 0 ){
            cout << "upload\n";
            //receive the name of the file 
            char* fup_name;
            recvCryptoString(tcp_client, fup_name);
            //recvl(tcp_client, fup_name);

            //build the path
            string path = "serverDir/";
            path = path + fup_name;
            //receive the file and put to the path
            recvCryptoFileFrom(tcp_client, path.c_str());
        }
        else if(strcmp(buf, "down") == 0 ){
            cout << "download\n";
            //receive the name of the file
            char* fdw_name;
            recvCryptoString(tcp_client, fdw_name);
            //build the path
            string path = "serverDir/";
            path = path + fdw_name;
            //send the file to the client
            sendCryptoFileTo(tcp_client, path.c_str());
        }

        //operation over, close socket
        close(tcp_client);
        cout << "---------------------------------------\n";
    }

    close(server_sock);
    return 0;
}
