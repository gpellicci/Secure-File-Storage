#include "client.h"
#include "communication.h"
#include "checkInputs.h"

using namespace std;

int main(){   


    bool firstLoop = true;
    commands_available();

    while(1){
respawn:
        /* empty the std input on each loop except the first to avoid chained commands */
        if(firstLoop == false){            
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
        else
            firstLoop = false;

        // prompt
        cout << "\n>> ";

        //get op code 
        string opcode;
        cin >> opcode;   
        /* sanitize input */     
        if(!checkInputString(opcode, cmdMaxLen))
            return 1;
        

        //exit command
        if(strcmp(opcode.c_str(), "exit") == 0 || strcmp(opcode.c_str(), "quit") == 0 ){
            return 0;
        }
        /* screen clear */
        else if(strcmp(opcode.c_str(), "clear") == 0 ){
            system("clear");
            system("clear");
            goto respawn;
        }
        /* debugging diff tool */
        else if(strcmp(opcode.c_str(), "diff") == 0 ){
            string f;
            cin >> f;
            string cmd = "diff ";
            cmd = cmd + "serverDir/"+ f + " clientDir/" + f;
            cout << "cmd: " << cmd << "\n";
            system(cmd.c_str());
            goto respawn;
        }        
        /* debugging HMAC tool */
        else if(strcmp(opcode.c_str(), "hmac") == 0 ){
            cout << "Insert <server/client> <filename> <file_key>\n";
            string sc;
            cin >> sc;
            string f;
            cin >> f;
            string kfile;
            cin >> kfile;            
            string cmd = "echo -n \"$(cat " + sc + "Dir/" + f + ")\" | openssl sha256 -hmac " + kfile;
            cout << "cmd: " << cmd << "\n";
            system(cmd.c_str());
            cout << "\nhmac key: ";
            unsigned char* k;
            readKeyFromFile(k, 32, kfile.c_str());
            printHexKey(k, 32);
            goto respawn;
        }
        /* debugging keygen tool */
        else if(strcmp(opcode.c_str(), "keygen") == 0 ){
            string f;
            cin >> f;
            unsigned char* key_hmac;
            keyGenToFile(32, f.c_str());
            readKeyFromFile(key_hmac, 32, f.c_str());
            printHexKey(key_hmac, 32);
            goto respawn;
        }
        /* info about protocol */
        else if(strcmp(opcode.c_str(), "info") == 0 ){
            cout << "Encryption:\n\033[1;33mAES-256-cbc\033[0m\n";
            cout << "\tKey size: " << EVP_CIPHER_key_length(EVP_aes_256_cbc()) << "\n";
            cout << "\tBlock size: " << EVP_CIPHER_block_size(EVP_aes_256_cbc())<< "\n\n";
            cout << "HMAC:\n\033[1;33mSHA-256\033[0m\n";
            cout << "\tDigest size: " << EVP_MD_size(EVP_sha256()) << "\n";   
            goto respawn;
        }

        /* get filename for upload/download operation */
        string fname;
        if( checkUpDownOperation(opcode) ){
            cout << "Insert filename: ";
            cin >> fname;     
            if(!checkInputString(fname, filenameMaxLen))
                return 1;
        }

        /* establish connection to the server only if cmd is 'list', 'down', 'up' */
        int client_sock;
        if( checkRemoteOperation(opcode) ){
            client_sock = connectToServer(serverIp, serverPort);
            if(client_sock == -1){
                return 1;
            }
        }
        
        /* i am now connected to the server */

        /* list operation */
        if(strcmp(opcode.c_str(), "list") == 0 ){
            //send the opcode
            int len = sendCryptoString(client_sock, opcode.c_str());
            if(len == -1)
                goto respawn;
            
            //receive file list as .txt
            recvCryptoFileFrom(client_sock, "list.txt", "clientDir/.list");        
            cout << "File list:\n";
            //remove final line, which is just a * and cat the rest
            //allow you to send the file even if the directory is empty
            system("cat clientDir/.list/list.txt | grep -v \"\\*\"");
            //remove the file
            system("rm clientDir/.list/list.txt");
            //operation done, close socket
            close(client_sock);
        }
        /* upload operation */
        else if(strcmp(opcode.c_str(), "up") == 0 ){
            //send the op code
            int len = sendCryptoString(client_sock, opcode.c_str());
            //send the name of the file that you are going to upload            
            string fup_name = fname;
            sendCryptoString(client_sock, fup_name.c_str());
            
            //build the path of the file
            string path = "clientDir/";
            path = path + fup_name;
            //get the file locally and send it
            sendCryptoFileTo(client_sock, path.c_str());

            //operation done, close socket
            close(client_sock);
        }
        /* download operation */
        else if(strcmp(opcode.c_str(), "down") == 0 ){    
            //send the op code
            int len = sendCryptoString(client_sock, opcode.c_str());
            //send the name of the file that you are going to download
            string fdw_name = fname;
            sendCryptoString(client_sock, fdw_name.c_str());    
            //build the path of the file
            string path = "clientDir/" + fdw_name;            
            //receive the file and put to the path
            unsigned int file_len = recvCryptoFileFrom(client_sock, fdw_name.c_str(), "clientDir");

            //operation done, close socket
            close(client_sock);
        }        
        /* bad command issued */
        else{
            cout << "Command not found! Try with:\n";
            commands_available();
            goto respawn;
        }


    }

    return 0;
}

