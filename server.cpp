#include "server.h"
#include "communication.h"

using namespace std; 

int main(){
    struct sockaddr_in serverAddr;
	int server_sock;
	bool result = prepareSocket(serverAddr, server_sock);
	if(!result){
		cout << "ERRORE!\n";
        return 1;
	}

    while(1){
        //accept client connection
        struct sockaddr_in client;
        int c = sizeof(struct sockaddr_in);
        int tcp_client = accept(server_sock, (struct sockaddr *)&client, (socklen_t*)&c);
            if (tcp_client < 0){
                cout << "Accept failed\n";
                return 1;
            }
        printf("Accepted connection from %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

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
