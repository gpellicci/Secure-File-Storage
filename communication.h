#include "fileManipulation.h"

using namespace std;

const unsigned int LENGTH = 512;


bool sendCryptoSize(int sock, uint32_t len){

    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    uint32_t lmsg;

    
    printf("\033[1;32m[%luBytes]PlainSIZE is: \033[31;47m%u\033[0m\n", sizeof(uint32_t), len);
    cout << "\033[0m";
    lmsg = htonl(len);

    unsigned char* plaintext = (unsigned char*)&lmsg;
    unsigned char* ciphertext = (unsigned char*)malloc(sizeof(uint32_t));
	
	if(!ciphertext){
		perror("ERRORE:\n");
		return false;
	}

    int plaintext_len = sizeof(uint32_t);

    unsigned int ciphertext_len = encrypt(plaintext, plaintext_len, key, NULL, ciphertext);

    // Redirect our ciphertext to the terminal
    printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    //actually send:
    int ret = send(sock, ciphertext, ciphertext_len, 0);

    if(ret < 0 )
        return false;

    printf("\tCipherSIZE sent.\n");
    
    return true;    
}

uint32_t recvCryptoSize(int sock){
    

    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    const unsigned int ciphertext_len = 16;

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len); 
	if(!ciphertext){
		perror("ERRORE:\n");
		return -1;
	} 

    unsigned char* decryptedtext = (unsigned char*)malloc(sizeof(uint32_t)+16);
	if(!decryptedtext){
		perror("ERRORE:\n");
		return -1;
	}


    //receive the ciphertext
    int ret = recv(sock, ciphertext, ciphertext_len, 0);    
    if(ret < 0)
        return -1;

    // Redirect our ciphertext to the terminal
    printf("[%uBytes]CipherSIZE is:\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    //DECRYPTION
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, NULL, decryptedtext);

    //recompose the uint16_t from the byte array
    uint32_t len = (decryptedtext[3] << 24) | (decryptedtext[2] << 16) | (decryptedtext[1] << 8) | (decryptedtext[0]);
    //put to host format
    len = ntohl(len);
    //show       
    
    printf("\033[1;32mDecryptedSIZE: \033[31;47m%u\033[0m\n", len);    
    return len;    
}






int sendCryptoString(int sock, const char* buf){
    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";

    unsigned char* plaintext = (unsigned char*)malloc(strlen(buf)+1);
    strcpy((char*)plaintext, buf);
    plaintext[strlen(buf)] = '\0';
    unsigned int plaintext_len = strlen((char*)plaintext);

    printf("----------------- %s -----------------\n", (char*)plaintext);
    unsigned char* ciphertext = (unsigned char *) malloc(plaintext_len+16);

    unsigned int decryptedtext_len, ciphertext_len;
    // Encrypt utility function
    ciphertext_len = encrypt ((unsigned char*)buf, plaintext_len, key, NULL,
                                ciphertext);


    //send ciphertext size (secure)
    sendCryptoSize(sock, ciphertext_len);
    //send ciphertext

    // Redirect our ciphertext to the terminal 
    
    printf("\033[1;33m[%uBytes]Plain: \033[31;47m%s\033[0m\n", plaintext_len, (char*)plaintext);   

    printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    send(sock, ciphertext, ciphertext_len, 0);
    //sendl(sock, (const char*)ciphertext);
    printf("\tCiphertext sent.\n");


    printf("--------------------------------------\n");

    return ciphertext_len;

}

int recvCryptoString(int sock, char*& buf){
    printf("------------ Decrypting ------------\n");

    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    
    unsigned int ciphertext_len = recvCryptoSize(sock);
    if(ciphertext_len == -1){
        cout << "ERROR crypto\n";
        exit(1);
    }

    char* ciphertext = (char*)malloc(ciphertext_len);
    int count = recv(sock, ciphertext, ciphertext_len, 0); //todo

    if(count != ciphertext_len){
        cout << "ERROR crypto\n";
        exit(1);
    }


    // Redirect our ciphertext to the terminal
    printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    unsigned char* decryptedtext = (unsigned char*)malloc(ciphertext_len);

    // Decrypt the ciphertext
    int decryptedtext_len = decrypt((unsigned char*)ciphertext, ciphertext_len, key, NULL, decryptedtext);

    // Add a NULL terminator. We are expecting printable text
    decryptedtext[decryptedtext_len] = '\0';
    printf("\033[1;33m[%lu]Decrypted: \033[31;47m%s\033[0m\n", strlen((char*)decryptedtext), (char*)decryptedtext);

    buf = (char*)decryptedtext;

    printf("--------------------------------------\n");
    return decryptedtext_len;
    
}





void sendCryptoFileTo(int sock, const char* fs_name){    
    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    unsigned char key_hmac[]="0123456789012345678901234567891";
    char sdbuf[LENGTH]; 
    string path = fs_name;
    unsigned int len = getFileSize(path);

    unsigned int nBlocks = len / LENGTH;
    unsigned int additionalSize = nBlocks*16;
    unsigned int exceed = len % 16;
    if(exceed != 0)
        additionalSize += (16 - exceed);
    printf("nBlocks: %u\tadd: %u\tnewtot: %u\n", nBlocks, additionalSize, (len+additionalSize));
    len += additionalSize;
    
    //send file size
    if(sendCryptoSize(sock, len) == false)
        return;
    cout << "Sending file...\n";
    FILE *fs = fopen(fs_name, "r");
    if(fs == NULL){
        cout << "ERROR: File not found.\n";        
        return;
    }
    else{
        bzero(sdbuf, LENGTH); // TODO sostituire con memset();
        int fs_block_sz;
        int hash_size = EVP_MD_size(EVP_sha256());
        int blockCount = 0;
        unsigned char* digest;
        while((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0){
            cout << sdbuf;
            if(blockCount == 0)
                hmac_SHA256((unsigned char*)sdbuf, fs_block_sz, key_hmac, digest);
            else
                hmac_SHA256((unsigned char*)sdbuf, fs_block_sz, digest, digest);

            unsigned char* ciphertext = (unsigned char*)malloc(fs_block_sz+16);
            unsigned int ciphertext_len = encrypt((unsigned char*)sdbuf, fs_block_sz, key, NULL, ciphertext);
            
            cout << "cipherlen: "<<ciphertext_len<<"\tfs_block_sz: "<<fs_block_sz<<"\n";

    printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

            if(send(sock, ciphertext, ciphertext_len, 0) < 0){
                fprintf(stderr, "ERROR: Failed to send file. (errno = %d)\n", errno);
                break;
            }            
            cout << "Block #"<< blockCount << "\tsize: " << fs_block_sz << "\n";
            blockCount++;

            bzero(sdbuf, LENGTH);
        }

        fclose(fs);
        cout << "\tFile sent\n Sending hash..\n";
        
        sendCryptoString(sock, (const char*)digest);
        cout << "Hash sent.\n";
        printf("\n");
    }
}


//recv file with known length
unsigned int recvCryptoFileFrom(int sock, const char* fr_name){    
    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    unsigned char key_hmac[]="0123456789012345678901234567891";

    unsigned int remaining;
    const int LENGTH = 512+16;
    char* recvbuf[LENGTH];
    unsigned char* digest;

    //get file length
    remaining = recvCryptoSize(sock);
    //recv(sock, (void*)&remaining, sizeof(unsigned int), 0);
    if(remaining == 0){
        cout << "ERROR: File not found.\n";        
        return 0;
    }
    unsigned int size = remaining;

    FILE *fr = fopen(fr_name, "w");
    if(fr == NULL)
        printf("File '%s' cannot be opened", fr_name);
    else{
        unsigned int blockCount = 0;
        bzero(recvbuf, LENGTH); 
        int fr_block_sz = 0;
        while(remaining > 0){
            
            cout << "Block #"<< blockCount << "\tsize: ";

            int write_sz;
            if(remaining >= LENGTH){    //usual block
                fr_block_sz = recv(sock, recvbuf, LENGTH, 0);
                cout << LENGTH;
            }
            else{   //last block
                fr_block_sz = recv(sock, recvbuf, remaining, 0);
                cout << remaining%LENGTH;
            }

            cout << "/" << LENGTH << " Bytes\n";   

    printf("[%uBytes]Ciphertext is:\n", fr_block_sz);
    BIO_dump_fp (stdout, (const char *)recvbuf, fr_block_sz);


            unsigned char* plaintext = (unsigned char*)malloc(fr_block_sz + 16);
            unsigned int plaintext_len = decrypt((unsigned char*)recvbuf, fr_block_sz, key, NULL, plaintext);         
            if(blockCount == 0)
                hmac_SHA256(plaintext, plaintext_len, key_hmac, digest);
            else
                hmac_SHA256(plaintext, plaintext_len, digest, digest);

            write_sz = fwrite(plaintext, sizeof(char), plaintext_len, fr);
                
            if(write_sz < plaintext_len){
                cout << "File write failed.\n";
            }

            blockCount++;
            remaining -= fr_block_sz;

        }
        int hash_size = EVP_MD_size(EVP_sha256());
    }
    fclose(fr);
    cout << "\tFile received.\n"; 

    char* recvDigest;
    recvCryptoString(sock, recvDigest);
    if(compare_hmac_SHA256(digest, (unsigned char*)recvDigest))
        cout << "\033[1;32mFILE IS AUTHENTIC!\033[0m\n";
    else{
        cout << "\033[1;31mFILE AUTHENTICITY/INTEGRITY HAS BEEN COMPROMISED\n";
        string del = "rm ";
        del = del + fr_name;
        system(del.c_str());
        cout << "FILE DELETED\033[0m\n";
    }
  
    return size;       
    
}
