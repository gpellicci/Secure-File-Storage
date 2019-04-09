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

#include "client.h"
#include "cryptography.h"
#include "communication.h"
#include "checkInputs.h"

//constant definition
#define cmdMaxLen 10
#define filenameMaxLen 255

#define serverIp "127.0.0.1"
#define serverPort 9090
//-----------------------------------

using namespace std;

//------------------------------------------------

int main(){


    while(1){
        //prompt
        cout << "\n>> ";

        //get op code 
        string opcode;
        cin >> opcode;        
        if(!checkInputString(opcode, cmdMaxLen))
            return 1;
        

        //exit program condition
        if(strcmp(opcode.c_str(), "exit") == 0 || strcmp(opcode.c_str(), "quit") == 0 ){
            return 0;
        }

        //get filename for upload/download
        string fname;
        if(strcmp(opcode.c_str(), "up") == 0 || strcmp(opcode.c_str(), "down") == 0 ){
            cout << "Insert filename: ";
            cin >> fname;     
            if(!checkInputString(fname, filenameMaxLen))
                return 1;
        }


	// TODO const parametr in client.h??
        //establish connection to the server
        int client_sock = connectToServer(serverIp, serverPort);

        //send the op code
        int len = sendCryptoString(client_sock, opcode.c_str());

     
        if(strcmp(opcode.c_str(), "list") == 0 ){
            //receive file list as .txt
            recvCryptoFileFrom(client_sock, "clientDir/listDL/list.txt");        
            cout << "File list:\n";
            //remove final line, which is just a * and cat the rest
            //allow you to send the file even if the directory is empty
            system("cat clientDir/listDL/list.txt | grep -v \"\\*\"");
            //remove the file
            system("rm clientDir/listDL/list.txt");
        }
        else if(strcmp(opcode.c_str(), "up") == 0 ){
            //send the name of the file that you are going to upload            
            string fup_name = fname;
            sendCryptoString(client_sock, fup_name.c_str());
            //sendl(client_sock, fup_name.c_str());
            
            //build the path of the file
            string path = "clientDir/";
            path = path + fup_name;
            //get the file locally and send it
            sendCryptoFileTo(client_sock, path.c_str());
        }
        else if(strcmp(opcode.c_str(), "down") == 0 ){    
            //send the name of the file that you are going to download
            string fdw_name = fname;
            sendCryptoString(client_sock, fdw_name.c_str());    
            //build the path of the file
            string path = "clientDir/" + fdw_name;            
            //receive the file and put to the path
            recvCryptoFileFrom(client_sock, path.c_str());
        }
        else if(strcmp(opcode.c_str(), "info") == 0 ){
            cout << "AES-256-cbc\n";
            cout <<"Key size: " << EVP_CIPHER_key_length(EVP_aes_256_cbc());
            cout <<"\nBlock size: " << EVP_CIPHER_block_size(EVP_aes_256_cbc())<<"\n";

            char msg[] = "Poggers";
            unsigned char* digest;
            //message_digest_SHA256((unsigned char*)msg, strlen(msg), digest);            
            unsigned char key_hmac[]="0123456789012345678901234567891";
            hmac_SHA256((unsigned char*)msg, strlen(msg), key_hmac, digest);

            

        }

        //empty the cin buffer, so no chained command happens
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        //operation done, close socket
        close(client_sock);
    }

    return 0;
}
