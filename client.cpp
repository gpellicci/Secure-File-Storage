#include "client.h"
#include "communication.h"
#include "checkInputs.h"


using namespace std;


int main(){

    while(1){
    respawn:
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
        if(strcmp(opcode.c_str(), "clear") == 0 ){
            system("clear");
            system("clear");
            goto respawn;
        }
        if(strcmp(opcode.c_str(), "diff") == 0 ){
            string f;
            cin >> f;
            string cmd = "diff ";
            cmd = cmd + "serverDir/"+ f + " clientDir/" + f;
            cout << "cmd: " << cmd << "\n";
            system(cmd.c_str());
            goto respawn;
        }
        else if(strcmp(opcode.c_str(), "info") == 0 ){
            cout << "AES-256-cbc\n";
            cout <<"Key size: " << EVP_CIPHER_key_length(EVP_aes_256_cbc());
            cout <<"\nBlock size: " << EVP_CIPHER_block_size(EVP_aes_256_cbc())<<"\n";
            goto respawn;
        }

        //get filename for upload/download
        string fname;
        if(strcmp(opcode.c_str(), "up") == 0 || strcmp(opcode.c_str(), "down") == 0 ){
            cout << "Insert filename: ";
            cin >> fname;     
            if(!checkInputString(fname, filenameMaxLen))
                return 1;
        }

        //establish connection to the server
        int client_sock = connectToServer(serverIp, serverPort);
        if(client_sock == -1){
            return 1;
        }

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
            unsigned int file_len = recvCryptoFileFrom(client_sock, path.c_str());
        }

        //empty the cin buffer, so no chained command happens
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        //operation done, close socket
        close(client_sock);
    }

    return 0;
}
