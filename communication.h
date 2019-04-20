#include "fileManipulation.h"
#include "cryptography.h"

using namespace std;

const unsigned int LENGTH = 512;
const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
const int hmacSize = EVP_MD_size(EVP_sha256());
const size_t key_hmac_size = 32;


unsigned char *key = (unsigned char *)"01234567012345670123456701234567";
unsigned char *key_hmac = (unsigned char*)"012345678901234567890123456789123";

bool sendCryptoSize(int sock, uint32_t len){  
    cout << "Sending size...\n"; 
    uint32_t lmsg = htonl(len);

    printf("\033[1;32m[%luBytes]PlainSIZE is: \033[31;47m%u\033[0m\n\033[0m", sizeof(uint32_t), len);

    unsigned char* plaintext = (unsigned char*)malloc(sizeof(uint32_t) + hmacSize);
    unsigned char* ciphertext = (unsigned char*)malloc(blockSize + hmacSize); /* sizeof(uint32_t) < blockSize so: one block data and 2 blocks for digest */
    if(!plaintext || !ciphertext){
        perror("ERRORE:\n");
        free(plaintext);
        free(ciphertext);
        return false;
    }
    void* r = memcpy(plaintext, &lmsg, sizeof(uint32_t));
    if(r != plaintext){
        perror("ERRORE:\n");
        free(plaintext);
        free(ciphertext);
        return false;
    }
    
    /* compute hmac of the size */
    int ret = hmac_SHA256((char*)&lmsg, sizeof(uint32_t), key_hmac, plaintext+sizeof(uint32_t));
    if(ret != hmacSize){
        perror("ERRORE:\n");
        free(plaintext);
        free(ciphertext);
        return false;
    }
//cout << "SIZE'S hmac: ";
//printHex(plaintext+4, hmacSize);
    int plaintext_len = sizeof(uint32_t) + hmacSize;

    /* encrypt the size */
    int ciphertext_len = encrypt(plaintext, plaintext_len, key, NULL, ciphertext);
    if(ciphertext_len == -1){
        free(plaintext);
        free(ciphertext);
        return false;
    }
//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* send the encrypted size */
    ret = send(sock, ciphertext, ciphertext_len, 0);
    if(ret < 0 || ret != ciphertext_len){
        free(plaintext);
        free(ciphertext);
        return false;
    }

    printf("\tSIZE sent.\n");
    
    return true;    
}

uint32_t recvCryptoSize(int sock){        
    const unsigned int ciphertext_len = blockSize + hmacSize;
    cout << "Receiving size...\n";
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len); 
    unsigned char* hmac = (unsigned char*)malloc(hmacSize); 
    unsigned char* recv_hmac = (unsigned char*)malloc(hmacSize); 
    unsigned char* decryptedtext = (unsigned char*)malloc(sizeof(uint32_t) + blockSize + hmacSize);
	if(!ciphertext || !decryptedtext || !hmac || !recv_hmac){
		perror("ERRORE:\n");
        free(ciphertext);
        free(hmac);
        free(recv_hmac);
        free(decryptedtext);
		return 0;
	}

    //receive the ciphertext
    int ret = recv(sock, ciphertext, ciphertext_len, 0);    
    if(ret < 0 || ret != ciphertext_len){   //error || not all bytes received
        perror("ERRORE:\n");
        free(ciphertext);
        free(hmac);
        free(recv_hmac);
        free(decryptedtext);
        return 0;
    }

//printf("[%uBytes]CipherSIZE is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    //DECRYPTION (size + hmac)
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, NULL, decryptedtext);
    if(decryptedtext_len == -1){
        free(ciphertext);
        free(hmac);
        free(recv_hmac);
        free(decryptedtext);
        return 0;
    }

    //recompose the uint32_t from the byte array
    uint32_t len = (decryptedtext[3] << 24) | (decryptedtext[2] << 16) | (decryptedtext[1] << 8) | (decryptedtext[0]);
    len = ntohl(len);   //put to host format

    /* compute the hmac */
    ret = hmac_SHA256((char*)decryptedtext, sizeof(uint32_t), key_hmac, hmac);
    if(ret != hmacSize){        
        free(ciphertext);
        free(hmac);
        free(recv_hmac);
        free(decryptedtext);
        return 0;
    }

    /* retrieve the received hmac */
    void* r = memcpy(recv_hmac, decryptedtext + sizeof(uint32_t), hmacSize);
    if(r != recv_hmac){
        printf("memcpy error\n");
        free(ciphertext);
        free(hmac);
        free(recv_hmac);
        free(decryptedtext);
        return 0;
    }

    //debug print
    //cout << "SIZE'S hmac     : ";
    //printHex(hmac, 32);
    //cout << "SIZE'S recv_hmac: ";
    //printHex(recv_hmac, 32);

    /* verify hmac */
    if(compare_hmac_SHA256(hmac, recv_hmac)){
        printf("\033[1;32mSIZE is AUTHENTIC\033[0m\n");    
    }
    else{        
        printf("\033[1;31mFILE IS NOT AUTHENTIC\033[0m\n");
        len = 0;    //make the return 0
    }
    free(ciphertext);
    free(hmac);
    free(recv_hmac);
    free(decryptedtext);

    //show           
    //printf("\033[1;32mDecryptedSIZE: \033[31;47m%u\033[0m\n", len);    
    return len;    
}






int sendCryptoString(int sock, const char* buf){
    
    int buf_len = strlen(buf);

    unsigned char* ciphertext = (unsigned char *) malloc(buf_len + 1 + blockSize);
    unsigned char* plaintext = (unsigned char*)malloc(buf_len +1);
    if(!ciphertext || !plaintext){
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    strncpy((char*)plaintext, buf, buf_len);
    plaintext[buf_len] = '\0';

    unsigned int plaintext_len = strlen((char*)plaintext);

    //printf("----------------- %s -----------------\n", (char*)plaintext);

    unsigned int decryptedtext_len, ciphertext_len;
    // Encrypt utility function
    ciphertext_len = encrypt ((unsigned char*)buf, plaintext_len, key, NULL, ciphertext);
    if(ciphertext_len == -1){
        free(ciphertext);
        free(plaintext);
        return -1;
    }


    //send ciphertext size (secure)
    if(sendCryptoSize(sock, ciphertext_len) == false){
        free(ciphertext);
        free(plaintext);
        return -1;
    }    
    printf("Sending string...\n");
    printf("\033[1;33m[%uBytes]Plain: \033[31;47m%s\033[0m\n", plaintext_len, (char*)plaintext);   

//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//  _dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* send encrypted string */  
    int l = send(sock, ciphertext, ciphertext_len, 0);
    if(l < 0 || l != ciphertext_len){
        printf("Error send string.\n");
        free(ciphertext);
        free(plaintext);
        return -1;
    }
    //sendl(sock, (const char*)ciphertext);
    printf("\tSTRING sent.\n");
    //printf("--------------------------------------\n");
    
    free(ciphertext);
    free(plaintext);

    return ciphertext_len;

}

int recvCryptoString(int sock, char*& buf){
    unsigned int ciphertext_len = recvCryptoSize(sock);
    if(ciphertext_len == 0){
        perror("ERROR string\n");
        return -1;
    }

    printf("Receiving string...\n");

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    unsigned char* decryptedtext = (unsigned char*)malloc(ciphertext_len);
    if(!ciphertext || !decryptedtext){
        free(ciphertext);
        free(decryptedtext);
        perror("ERROR\n");
        return -1;
    }

    int count = recv(sock, ciphertext, ciphertext_len, 0); 
    if(count < 0 || count != ciphertext_len){
        free(ciphertext);
        free(decryptedtext);
        perror("ERROR crypto\n");
        return -1;
    }

//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // Decrypt the ciphertext
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, NULL, decryptedtext);
    if(decryptedtext_len == -1){
        free(ciphertext);
        free(decryptedtext);
        return -1;
    }
    // Add a NULL terminator. We are expecting printable text
    decryptedtext[decryptedtext_len] = '\0';
    printf("\033[1;33m[%lu]Decrypted String: \033[31;47m%s\033[0m\n", strlen((char*)decryptedtext), (char*)decryptedtext);

    buf = (char*)decryptedtext;

    return decryptedtext_len;
}



unsigned int sendCryptoFileTo(int sock, const char* fs_name){    
    string path = fs_name;

    /* Compute file size */
    unsigned int len;
    if(getFileSize(path, len) == false)
        return 0;
    
    /* Compute block number */
    unsigned int nFrags = len / LENGTH;
    if((len % LENGTH)>0)
        nFrags++;
        
    /* Send file size */
    if(sendCryptoSize(sock, len) == false)
        return 0;

    /*debug*/
    unsigned int cipherSize = len + 16 - (len %16);
    //cout << "ciphersize: " << cipherSize << "\n";
    //cout << "nFrags: "<<nFrags<<"\n";

    /* malloc all buffers */
    unsigned char* sdbuf = (unsigned char*)malloc(LENGTH + hmacSize); /* blockSize + hmacSize */
    unsigned char* ciphertext = (unsigned char*)malloc(LENGTH + blockSize + hmacSize); 
    unsigned char* hmac = (unsigned char*)malloc(hmacSize);
    if(!sdbuf || !ciphertext || !hmac){
        perror("ERROR:\n");
        free(sdbuf);
        free(ciphertext);
        free(hmac);
        return 0;
    }



// ENCRYPTION
    EVP_CIPHER_CTX *ctx;
    unsigned char* iv = NULL;
    int tmp_len;
    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
        free(sdbuf);
        free(ciphertext);
        free(hmac);
        return 0;
    }
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){        
        handleErrors();
        free(sdbuf);
        free(ciphertext);
        free(hmac);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

// HMAC
    HMAC_CTX* mdctx;
    //readKeyFromFile(key_hmac, hmacSize, "mykey");
    //cout << "key: " << key_hmac_size << "\n";
    //printHexKey(key_hmac, key_hmac_size);
    if(!(mdctx = HMAC_CTX_new())){
        handleErrors();
        free(sdbuf);
        free(ciphertext);
        free(hmac);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if(1 != HMAC_Init_ex(mdctx, key_hmac, key_hmac_size, EVP_sha256(), NULL)){
        handleErrors();        
        free(sdbuf);
        free(ciphertext);
        free(hmac);
        HMAC_CTX_free(mdctx);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    cout << "Sending file...\n";

    FILE *fs = fopen(fs_name, "r");
    if(fs == NULL){
        cout << "ERROR: File not found.\n";        
        return 0;
    }
    else{
        memset(sdbuf, 0, LENGTH);
        int fs_block_sz, ciphertext_len;
        int blockCount = 0;
        int totCipherLen = 0;   //debug
        int totSentLen = 0;     //debug
        unsigned int hmac_len;
        while((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0){
            cout << "Block #"<< blockCount << "\tsize: " << fs_block_sz << "\n";

            /* digest of plaintext fragment */
            if(1 != HMAC_Update(mdctx, sdbuf, fs_block_sz)){
                handleErrors();                
                free(sdbuf);
                free(ciphertext);
                free(hmac);                
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx);
                fclose(fs);
                return 0;
            }

            //cout << "hmac on: " << fs_block_sz << " bytes\n";

            /* last block, finalize HMAC */
            if(nFrags == (blockCount + 1)){
                if(1 != HMAC_Final(mdctx, hmac, &hmac_len)){
                    handleErrors();                    
                    free(sdbuf);
                    free(ciphertext);
                    free(hmac);
                    HMAC_CTX_free(mdctx);
                    EVP_CIPHER_CTX_free(ctx);
                    fclose(fs);
                    return 0;
                }
                //printf("hmac len %u\n", hmac_len);
                /* concat hmac to the send buffer */
                void* r = memcpy(sdbuf + fs_block_sz, hmac, hmacSize);
                if((sdbuf+fs_block_sz) != r){
                    perror("memcpy. Error");                    
                    free(sdbuf);
                    free(ciphertext);
                    free(hmac);
                    HMAC_CTX_free(mdctx);
                    EVP_CIPHER_CTX_free(ctx);
                    fclose(fs);
                    return 0;
                }
                fs_block_sz += hmacSize;
            }


            /* encrypt */
            if(1 != EVP_EncryptUpdate(ctx, ciphertext, &tmp_len, (unsigned char*)sdbuf, fs_block_sz)){
                handleErrors();                        
                free(sdbuf);
                free(ciphertext);
                free(hmac);                
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx);
                fclose(fs);
                return 0;
            }
            ciphertext_len = tmp_len;   
         
            /* finalize the encryption */
            if(nFrags == (blockCount + 1)){
                //cout << "**Final block\n";
                if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &tmp_len)){
                    handleErrors();                    
                    free(sdbuf);
                    free(ciphertext);
                    free(hmac);
                    HMAC_CTX_free(mdctx);
                    EVP_CIPHER_CTX_free(ctx);
                    fclose(fs); 
                    return 0;
                }
                ciphertext_len += tmp_len;
            }


            //cout << "ciphertext_len: " << ciphertext_len << "\n";
//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

            /* send the encrypted file fragment */
            int l = send(sock, ciphertext, ciphertext_len, 0);
            if(l < 0 || l != ciphertext_len){
                perror("ERROR: Failed to send file.\n");
                free(sdbuf);
                free(ciphertext);
                free(hmac);
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx);
                fclose(fs);
                return 0;                
            }     
            /* debug */
            totSentLen += l;
            totCipherLen += ciphertext_len;

            blockCount++;
            memset(sdbuf, 0, LENGTH);
        }
        /* close file */
        int ret = fclose(fs);
        if(ret != 0){
            handleErrors();                    
            free(sdbuf);
            free(ciphertext);
            free(hmac);
            HMAC_CTX_free(mdctx);
            EVP_CIPHER_CTX_free(ctx);            
            return 0;
        }
        /* free context */
        HMAC_CTX_free(mdctx);
        EVP_CIPHER_CTX_free(ctx);


        cout << "\tFile sent\n";
        //cout << "FILE'S hmac: ";
        //printHex(hmac, hmacSize);
        
        //cout << "CipherlenTotal: " << totCipherLen << "\n";
        //cout << "totSentLen: " << totSentLen << "\n";
        
        /* return file length if ok */
        return len;  
    }
}


//recv file with known length
unsigned int recvCryptoFileFrom(int sock, const char* fr_name, const char* dir_name){    

    /* path strings to handle hmac verification */
    string tmp_path (dir_name);
    tmp_path = tmp_path + "/.tmp/" + fr_name;
    string perm_path (dir_name);
    perm_path = perm_path + "/" + fr_name;

    /* receive file length */
    unsigned int size;
    size = recvCryptoSize(sock);
    if(size == 0){
        cout << "ERROR: File not found.\n";        
        return 0;
    }

    /* size is the plainfile size */
    unsigned int remaining = size;
    //cout << "filesize: " << size <<"\n";

    /* remaining represent the amount of ciphertext that i still have to receive */
    /* padding block + hmac */
    remaining = remaining + blockSize + hmacSize;    
    if((size % LENGTH) != 0)
        remaining = remaining - (size % blockSize);
    
    /* number of fragments to receive */ 
    unsigned int nFrags = remaining / LENGTH;
    if((remaining % LENGTH) != 0)
        nFrags++;

    //cout << "remaining: "<<remaining<<"\n";
    //cout << "nFrags: "<<nFrags<<"\n";


// encryption 
    EVP_CIPHER_CTX *ctx;
    unsigned char* iv = NULL;
    int tmp_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
        return 0;
    }
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

// HMAC
    HMAC_CTX* mdctx;
    //readKeyFromFile(key_hmac, hmacSize, "mykey");
    //cout << "key: " << hmacSize << "\n";
    //printHexKey(key_hmac, hmacSize);
    if(!(mdctx = HMAC_CTX_new())){
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if(1 != HMAC_Init_ex(mdctx, key_hmac, hmacSize, EVP_sha256(), NULL)){        
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        HMAC_CTX_free(mdctx);
        return 0;
    }


    cout << "Receiving file...\n";

    FILE *fr = fopen(tmp_path.c_str(), "w");
    if(fr == NULL){
        printf("File cannot be opened");
        EVP_CIPHER_CTX_free(ctx);
        HMAC_CTX_free(mdctx);
        return 0;
    }
    else{
        unsigned int blockCount = 0;
        int fr_block_sz = 0; 
        int plaintext_len;
        //todo blocksize necessario?
        char* recvbuf = (char*)malloc(LENGTH + blockSize + hmacSize); 
        unsigned char* plaintext = (unsigned char*)malloc(LENGTH + blockSize + hmacSize);
        unsigned char* recv_hmac = (unsigned char*)malloc(hmacSize);
        unsigned char* hmac = (unsigned char*)malloc(hmacSize);        
        if(!recvbuf || !plaintext || !recv_hmac || !hmac){
            printf("malloc error\n");
            free(recvbuf);
            free(plaintext);
            free(recv_hmac);
            free(hmac);
            HMAC_CTX_free(mdctx);
            EVP_CIPHER_CTX_free(ctx); 
            fclose(fr);
            system((string("rm ") + tmp_path).c_str());
            return 0;
        }
        
        while(remaining > 0){            
            int write_sz, recv_len;

            /* full fragment 512 byte */
            if(remaining >= LENGTH){    
                //cout << "**fullblock\n";
                recv_len = LENGTH;
            }
            /* not full fragment -> last one */
            else{   //last block has different size in general, considering also possible padding            
                //cout << "*****partial block\n";
                recv_len = remaining;
            }

            /* recv the ciphertext */
            fr_block_sz = recv(sock, recvbuf, recv_len, 0);
            if(fr_block_sz == -1 || fr_block_sz != recv_len){
                perror("Socket issue. Error");
                free(recvbuf);
                free(plaintext);
                free(recv_hmac);
                free(hmac);
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx); 
                fclose(fr);
                system((string("rm ") + tmp_path).c_str());
                return 0;
            }

            /* debug */
            //cout << "\trecv: " << fr_block_sz << "\n";            
            cout << "Block #"<< blockCount <<"\tremaining "<<remaining - fr_block_sz <<"\tsize: " << fr_block_sz << "/" << LENGTH << " Bytes\n";   

            /* decrypt the fragment */
            if(1 != EVP_DecryptUpdate(ctx, plaintext, &tmp_len, (unsigned char*)recvbuf, fr_block_sz)){
                handleErrors();
                free(recvbuf);
                free(plaintext);
                free(recv_hmac);   
                free(hmac);             
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx);
                fclose(fr);
                system((string("rm ") + tmp_path).c_str());
                return 0;
            }
            plaintext_len = tmp_len;                
            //cout << "plaintext_len: " << plaintext_len << "\n";  


            /* last block -> finalize and free the context */
            if(nFrags == (blockCount + 1)){ 
                if(1 != EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &tmp_len)){
                    handleErrors();
                    free(recvbuf);
                    free(plaintext);
                    free(recv_hmac);
                    free(hmac);
                    HMAC_CTX_free(mdctx);
                    EVP_CIPHER_CTX_free(ctx);
                    fclose(fr);
                    system((string("rm ") + tmp_path).c_str());
                    return 0;
                }
                plaintext_len += tmp_len;                 

                //cout << "tmp_len: " << tmp_len << "\n";
                //cout << "plaintext_len: " << plaintext_len << "\n";                                                                  
                //cout << "----------finalized\n";

                plaintext_len -= hmacSize;
                void* r = memcpy(recv_hmac, plaintext + plaintext_len, hmacSize);
                if(recv_hmac != r){
                    perror("memcpy. Error");
                    free(recvbuf);
                    free(plaintext);
                    free(recv_hmac);
                    free(hmac);
                    HMAC_CTX_free(mdctx);
                    EVP_CIPHER_CTX_free(ctx);                    
                    fclose(fr);
                    system((string("rm ") + tmp_path).c_str());
                    return 0;
                }
            }
            

//printf("[%uBytes]ciphertext is:\n", fr_block_sz);
//BIO_dump_fp (stdout, (const char *)recvbuf, fr_block_sz);
        
            /* digest of plaintext fragment */
            if(1 != HMAC_Update(mdctx, plaintext, plaintext_len)){
                handleErrors();
                free(recvbuf);
                free(plaintext);
                free(recv_hmac);
                free(hmac);
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx);                    
                fclose(fr);
                system((string("rm ") + tmp_path).c_str());
                return 0;
            }

            /* write to file the just decrypted plaintext */            
            write_sz = fwrite(plaintext, sizeof(char), plaintext_len, fr);                
            if(write_sz != plaintext_len){
                perror("File write failed.\n");
                free(recvbuf);
                free(plaintext);
                free(recv_hmac);                
                free(hmac);
                HMAC_CTX_free(mdctx);
                EVP_CIPHER_CTX_free(ctx);                     
                fclose(fr);
                system((string("rm ") + tmp_path).c_str());
                return 0;
            }

            remaining -= fr_block_sz;
            blockCount++;
            //printf("remaning %d\n",remaining);
        }

        unsigned int hmac_len;     
        if(1 != HMAC_Final(mdctx, hmac, &hmac_len)){
            handleErrors();
            free(recvbuf);
            free(plaintext);
            free(recv_hmac);                
            free(hmac);
            HMAC_CTX_free(mdctx);
            EVP_CIPHER_CTX_free(ctx);                     
            fclose(fr);
            system((string("rm ") + tmp_path).c_str());
            return 0;
        }
        //printf("hmac len %u\n", hmac_len);               

    cout << "FILE'S hmac:      ";
    printHex(hmac, hmacSize);
    cout <<"FILE'S recv_hmac: ";
    printHex(recv_hmac, hmacSize);

        /* equal hmac -> authentic */
        if(compare_hmac_SHA256(hmac, recv_hmac)){
            cout << "\033[1;32mFILE IS AUTHENTIC\033[0m\n";
            string cmd = "mv ";
            cmd = cmd + dir_name + "/.tmp/" + fr_name + " " + dir_name + "/";
            system(cmd.c_str());
            cout << "\tFile stored.\n"; 
        }
        else{
            cout << "\033[1;31mFILE IS NOT AUTHENTIC\n";
            string cmd = "rm ";
            cmd = cmd + dir_name + "/.tmp/" + fr_name;
            system(cmd.c_str());
            cout << "\tFILE DELETED.\033[0m\n";
        }

        /* free memory */
        free(plaintext);
        free(recvbuf);
        free(recv_hmac);                
        free(hmac);
        /* free context */
        HMAC_CTX_free(mdctx);
        EVP_CIPHER_CTX_free(ctx);  
        
        int ret = fclose(fr);
        if(ret != 0){
            perror("Could not close the file.\n");
            return 0;
        }
        return size; 
    }
}

