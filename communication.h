#include "fileManipulation.h"
#include "cryptography.h"

using namespace std;

const unsigned int LENGTH = 512;
const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());


bool sendCryptoSize(int sock, uint32_t len){

    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    uint32_t lmsg;

    
    printf("\033[1;32m[%luBytes]PlainSIZE is: \033[31;47m%u\033[0m\n\033[0m", sizeof(uint32_t), len);

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
//printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

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
		return 0;
	} 

    unsigned char* decryptedtext = (unsigned char*)malloc(sizeof(uint32_t)+16);
	if(!decryptedtext){
		perror("ERRORE:\n");
		return 0;
	}


    //receive the ciphertext
    int ret = recv(sock, ciphertext, ciphertext_len, 0);    
    if(ret < 0)
        return 0;

    // Redirect our ciphertext to the terminal
//printf("[%uBytes]CipherSIZE is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

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

//printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
//  _dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
  
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
//printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

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

    unsigned int len;
    getFileSize(path, len);

    unsigned int nBlocks = len / LENGTH;
    if((len % LENGTH)>0)
        nBlocks++;
        
    //send file size
    if(sendCryptoSize(sock, len) == false)
        return;
    cout << "Sending file...\n"; 

    /*debug*/
    unsigned int cipherSize = len + 16 - (len %16);
    cout << "ciphersize: " << cipherSize << "\n";
    cout << "nBlocks: "<<nBlocks<<"\n";

    EVP_CIPHER_CTX *ctx;
    unsigned char* iv = NULL;
    int tmp_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();


    FILE *fs = fopen(fs_name, "r");
    if(fs == NULL){
        cout << "ERROR: File not found.\n";        
        return;
    }
    else{
        bzero(sdbuf, LENGTH); // TODO sostituire con memset();
        int fs_block_sz;
        int blockCount = 0;
        int ciphertext_len;
        int totCipherLen = 0;
        int totSentLen = 0;
        unsigned char* ciphertext = (unsigned char*)malloc(LENGTH + blockSize);
        while((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0){
            cout << "Block #"<< blockCount << "\tsize: " << fs_block_sz << "\n";


            if(1 != EVP_EncryptUpdate(ctx, ciphertext, &tmp_len, (unsigned char*)sdbuf, fs_block_sz))
                handleErrors();
            ciphertext_len = tmp_len;   
         
            if(nBlocks == (blockCount + 1)){
                cout << "**Final block\n";
                if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &tmp_len)) 
                    handleErrors();
                ciphertext_len += tmp_len;
            }


            cout << "ciphertext_len: " << ciphertext_len << "\n";
//printf("[%uBytes]Ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

            int l;
            if( (l = send(sock, ciphertext, ciphertext_len, 0)) < 0){
                fprintf(stderr, "ERROR: Failed to send file. (errno = %d)\n", errno);
                break;
            }     
            cout << "\tsent: " << l <<"\n";

            totSentLen += l;
            totCipherLen += ciphertext_len;
            blockCount++;

            bzero(sdbuf, LENGTH);
        }
        fclose(fs);

        cout << "\tFile sent\n Sending hash..\n";

        cout << "CipherlenTotal: " << totCipherLen << "\n";
        cout << "totSentLen: " << totSentLen << "\n";
        
    }
}


//recv file with known length
unsigned int recvCryptoFileFrom(int sock, const char* fr_name){    
    unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
    unsigned char key_hmac[]="0123456789012345678901234567891";

    unsigned int remaining;
    char* recvbuf = (char*)malloc(LENGTH + blockSize); 
    //get file length
    remaining = recvCryptoSize(sock);
    if(remaining == 0){
        cout << "ERROR: File not found.\n";        
        return 0;
    }

    /* size if the plain file size */
    unsigned int size = remaining;
    cout << "filesize: " << size <<"\n";

    

    /* remaining represent the amount of ciphertext that i still have to receive */
    remaining = remaining + 16;    
    if((size % LENGTH) != 0)
        remaining = remaining - (size % blockSize);
    
    /* number of fragments to receive */ 
    unsigned int nBlocks = remaining / LENGTH;
    if((remaining % LENGTH) != 0)
        nBlocks++;

    cout << "remaining: "<<remaining<<"\n";
    cout << "nBlocks: "<<nBlocks<<"\n";



    EVP_CIPHER_CTX *ctx;
    unsigned char* iv = NULL;
    int tmp_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();


    FILE *fr = fopen(fr_name, "w");
    if(fr == NULL)
        printf("File '%s' cannot be opened", fr_name);
    else{
        unsigned int blockCount = 0;
        int fr_block_sz = 0; 
        int plaintext_len;
        unsigned char* plaintext = (unsigned char*)malloc(LENGTH + blockSize);
        
        while(remaining > 0){            
            int write_sz, recv_len;

            /* full fragment 512byte */
            if(remaining >= LENGTH){    //usual block
                cout << "**fullblock\n";
                recv_len = LENGTH;
            }
            /* not full fragment -> last one */
            else{   //last block has different size in general, considering also possible padding            
                cout << "*****partial block\n";
                recv_len = remaining;
            }

            /* recv the ciphertext */
            fr_block_sz = recv(sock, recvbuf, recv_len, 0);
            if(fr_block_sz == -1){
                perror("Socket issue. Error");
            }

            cout << "\trecv: " << fr_block_sz << "\n";
            /* debug */
            cout << "Block #"<< blockCount <<"\tremaining "<<remaining - fr_block_sz <<"\tsize: " << fr_block_sz << "/" << LENGTH << " Bytes\n";   

            /* decrypt the fragment */
            if(1 != EVP_DecryptUpdate(ctx, plaintext, &tmp_len, (unsigned char*)recvbuf, fr_block_sz))
                handleErrors();
            plaintext_len = tmp_len;                
            cout << "plaintext_len: " << plaintext_len << "\n";  


            /* last block -> finalize and free the context */
            if(nBlocks == (blockCount + 1)){ 
                if(1 != EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &tmp_len)) 
                    handleErrors();
                plaintext_len += tmp_len;                 

                cout << "tmp_len: " << tmp_len << "\n";
                cout << "plaintext_len: " << plaintext_len << "\n";                                
                                  
                cout << "----------finalized\n";
            }

            if(nBlocks == blockCount){    
                cout << "context freed";            
                EVP_CIPHER_CTX_free(ctx);                 
            }                

//printf("[%uBytes]Ciphertext is:\n", fr_block_sz);
//BIO_dump_fp (stdout, (const char *)recvbuf, fr_block_sz);
        
            /* write to file the just decrypted plaintext */
            write_sz = fwrite(plaintext, sizeof(char), plaintext_len, fr);
                
            if(write_sz < plaintext_len){
                cout << "File write failed.\n";
            }

            remaining -= fr_block_sz;
            blockCount++;
            printf("remaning %d\n",remaining);


        }
        /* free memory */
        free(plaintext);
        free(recvbuf);

    }

    fclose(fr);
    cout << "\tFile received.\n"; 

    return size;       
    
}

