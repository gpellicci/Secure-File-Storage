#include "client.h"
#include "communication.h"
#include "checkInputs.h"


using namespace std;


void commands_available(){

    cout << "\033[1;33mCOMMANDS\033[0m\n";
    cout << "'list' to have a list of file available on the server\n";  
    cout << "'down filename' to download file filename from the server\n";  
    cout << "'up filename' to upload file filename on the server\n";  
    cout << "'info' to have some information about the protocol\n";  
    cout << "'quit' or 'exit' to terminate the program\n";  
}


int main(){   

/*
    FILE* fs = fopen("serverDir/gg.c", "r");
    unsigned char* sdbuf = (unsigned char*)malloc(512);    
    unsigned char* k = (unsigned char*)malloc(32);
    unsigned char* md = (unsigned char*)malloc(32);
    k = (unsigned char *)"0123456789012345678901234567891";
    
    //readKeyFromFile(k, 32, "mykey");
    int fs_block_sz;
    HMAC_CTX* mdctx = HMAC_CTX_new();
    HMAC_Init_ex(mdctx, k, 32, EVP_sha256(), NULL);
    while((fs_block_sz = fread(sdbuf, sizeof(char), 512, fs)) > 0){  
        cout << "byte "<<fs_block_sz<<"\n";
        HMAC_Update(mdctx, sdbuf, fs_block_sz);
    }
    unsigned int md_len;
    HMAC_Final(mdctx, md, &md_len);
    printf("Hmac -> ");
    printHexKey(md, 32);
    
cout << "--------------------------------\n\n\n\n\n";
    fileHmac("serverDir/short");
/*
    const char* msg = "Short message";
    unsigned char* key = (unsigned char*)"01234567890123456789012345678912";
    unsigned char* md = (unsigned char*)malloc(32);
    hmac_SHA256((char*)msg, 13, key, md);
    printHexKey(md, 32);

cout << "--------------------------------\n\n\n\n\n";
*/

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
        

        /* list operation */
        if(strcmp(opcode.c_str(), "list") == 0 ){
            //send the op code
            int len = sendCryptoString(client_sock, opcode.c_str());
            //receive file list as .txt
            recvCryptoFileFrom(client_sock, "clientDir/listDL/list.txt");        
            cout << "File list:\n";
            //remove final line, which is just a * and cat the rest
            //allow you to send the file even if the directory is empty
            system("cat clientDir/listDL/list.txt | grep -v \"\\*\"");
            //remove the file
            system("rm clientDir/listDL/list.txt");
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
            unsigned int file_len = recvCryptoFileFrom(client_sock, path.c_str());

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

