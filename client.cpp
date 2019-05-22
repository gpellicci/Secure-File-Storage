#include "client.h"
#include "communication.h"
#include "checkInputs.h"
#include "sts.h"

using namespace std;

int main(){   
    bool firstLoop = true;
    //commands_available();
    int client_sock = connectToServer(serverIp, serverPort);
    if(client_sock == -1){
        return 1;
    }

    //KEY EXCHANGE Station-to-Station
    bool sts = stsInitiator(client_sock);
    if(!sts){
        close(client_sock);
        return 1;
    }

    /* i am now connected to the server */

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
        
        /* screen clear */
        if(strcmp(opcode.c_str(), "clear") == 0 ){
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
        /* info about protocol */
        else if(strcmp(opcode.c_str(), "info") == 0 ){
            cout << "Station-to-Station Diffie-Hellman key exchange protocol with direct authentication\n";
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

        /* send command to the server only if cmd is 'list', 'down', 'up' */
        if( checkRemoteOperation(opcode) ){
            //send to the server the opcode
            int len = sendCryptoString(client_sock, opcode.c_str());
            if(len == -1)
                goto respawn;

            /* list operation */
            if(strcmp(opcode.c_str(), "list") == 0 ){                
                //receive file list as .txt
                int err;
                unsigned int ret;
                ret = recvCryptoFileFrom(client_sock, "list.txt", "clientDir/.list", err);        
                if(ret != 0 && err == 2){
                    cout << "File list:\n";
                    //Remove the final line, which is just a * and cat the rest
                    //allow you to send the file even if the directory is empty
                    system("cat clientDir/.list/list.txt | grep -v \"\\*\"");
                }
                //remove the file
                system("rm clientDir/.list/list.txt");  
                if(err == 1){
                    goto respawn;
                }
                if(err == 0){
                    printf("Error receiving the file\n");
                    goto close;
                }              
            }
            /* upload operation */
            else if(strcmp(opcode.c_str(), "up") == 0 ){
                unsigned int ret;
                //send the name of the file that you are going to upload            
                string fup_name = fname;
                ret = sendCryptoString(client_sock, fup_name.c_str());
                if(ret == -1)
                    goto respawn;
                printf("Filename issued\n\n");

                
                //build the path of the file
                string path = "clientDir/";
                path = path + fup_name;

                //get the file locally and send it
                int err;
                sendCryptoFileTo(client_sock, path.c_str(), err);
                if(err == 1){
                    printf("File not found\n");
                    goto respawn;
                }
                if(err == 0){
                    printf("Error sending the file\n");
                    goto close;
                }   
            }
            /* download operation */
            else if(strcmp(opcode.c_str(), "down") == 0 ){    
                unsigned int ret;
                //send the name of the file that you are going to download
                string fdw_name = fname;
                ret = sendCryptoString(client_sock, fdw_name.c_str());
                if(ret == -1)
                    goto respawn;
                printf("Filename issued\n\n");           

                //receive the file and put to the path
                int err;
                recvCryptoFileFrom(client_sock, fdw_name.c_str(), "clientDir", err);
                if(err == 1){
                    goto respawn;
                }
                if(err == 0){
                    printf("Error receiving the file\n");
                    goto close;
                }   
            }           
        }
        /* bad command issued */
        else{ 
            cout << "Command not found! Try with:\n";
            commands_available();
        }


    }

close:
    close(client_sock);
    free(key);
    free(key_hmac);
    return 0;
}

