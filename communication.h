#include "fileManipulation.h"
#include "cryptography.h"

using namespace std;

const unsigned int LENGTH = 520;
const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
const int hmacSize = EVP_MD_size(EVP_sha256());
const unsigned int key_hmac_size = 32;


unsigned char *key = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_256_cbc()));
unsigned char *key_hmac = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_256_cbc()));
uint64_t sequenceNumber;

bool sendCryptoSize(int sock, uint64_t len){
    uint64_t lmsg = htobe64(len);   //convert length to network byte order (big endian)
    uint64_t count = htobe64(sequenceNumber);
    void* r;
    int plaintext_len, ciphertext_len, ret;
    unsigned char* plaintext = (unsigned char*)malloc(sizeof(uint64_t) + sizeof(uint64_t) + hmacSize);
    unsigned char* ciphertext = (unsigned char*)malloc(sizeof(uint64_t) + sizeof(uint64_t) + hmacSize + blockSize); 
    unsigned char* iv = NULL;
    //generate the IV at random
    if(!keyGen(iv, blockSize)) 
        goto sendCryptoSizeQuit;

    if(!plaintext || !ciphertext)
        goto sendCryptoSizeQuit;

    r = memcpy(plaintext, &count, sizeof(uint64_t));
    if(!r)
        goto sendCryptoSizeQuit;
    r = memcpy(plaintext + sizeof(uint64_t), &lmsg, sizeof(uint64_t));
    if(!r)
        goto sendCryptoSizeQuit;
    //compute size's hmac    
    ret = hmac_SHA256((char*)plaintext, 2*sizeof(uint64_t), key_hmac, plaintext + 2*sizeof(uint64_t));
    if(ret != hmacSize)
        goto sendCryptoSizeQuit;

    plaintext_len = 2*sizeof(uint64_t) + hmacSize;
    //encrypt the size|hmac(size)
    ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext, EVP_aes_256_cbc());
    if(ciphertext_len == -1)
        goto sendCryptoSizeQuit;

    /* send IV */
    ret = send(sock, iv, blockSize, 0);
    if(ret < 0 || ret != blockSize)
        goto sendCryptoSizeQuit;

    /* send ciphertext */
    ret = send(sock, ciphertext, ciphertext_len, 0);
    sequenceNumber++;
    if(ret < 0 || ret != ciphertext_len)
        goto sendCryptoSizeQuit;
    free(plaintext);
    free(ciphertext);
    free(iv);
//    cout << "size sent: "<<sequenceNumber-1 <<"\t"<<len<<"\t"<<ciphertext_len<<"\n";
    return true;

/* error handling */
sendCryptoSizeQuit:    
    free(plaintext);
    free(ciphertext);
    free(iv);
    return false;
}

uint64_t recvCryptoSize(int sock){
    const unsigned int ciphertext_len = blockSize + blockSize + hmacSize;
    void* r;
    uint64_t h_len, len, recv_count, recv_seqNum;
    int decryptedtext_len,ret;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len); 
    unsigned char* hmac = (unsigned char*)malloc(hmacSize); 
    unsigned char* recv_hmac = (unsigned char*)malloc(hmacSize); 
    unsigned char* decryptedtext = (unsigned char*)malloc(ciphertext_len);
    unsigned char* iv = (unsigned char*)malloc(blockSize);
    if(!ciphertext || !hmac || !recv_hmac || !decryptedtext || !iv)
        goto recvCryptoSizeQuit;

    // receive IV 
    ret = recv(sock, iv, blockSize, MSG_WAITALL);  
    if(ret < 0 || ret != blockSize)   //error || not all bytes received
        goto recvCryptoSizeQuit;
    // receive the ciphertext
    ret = recv(sock, ciphertext, ciphertext_len, MSG_WAITALL);    
    if(ret < 0 || ret != ciphertext_len)   //error || not all bytes received
        goto recvCryptoSizeQuit;
    //decrypt ciphertext
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext, EVP_aes_256_cbc());
    if(decryptedtext_len == -1)
        goto recvCryptoSizeQuit;
    //compute hmac of the plaintext
    ret = hmac_SHA256((char*)decryptedtext, 2*sizeof(uint64_t), key_hmac, hmac);
    if(ret != hmacSize)
        goto recvCryptoSizeQuit;
    //retrieve the received hmac
    r = memcpy(recv_hmac, decryptedtext + 2*sizeof(uint64_t), hmacSize);
    if(!r)
        goto recvCryptoSizeQuit;
    //retrieve the message payload (size) and convert to host byte order
    memcpy(&len, decryptedtext + sizeof(uint64_t), sizeof(uint64_t));
    h_len = be64toh(len);       
    memcpy(&recv_count, decryptedtext, sizeof(uint64_t));
    recv_seqNum = be64toh(recv_count);
    if(recv_seqNum != sequenceNumber){
        goto recvCryptoSizeQuit;
    }
//memset(hmac, 0, hmacSize);    //to make hmac check fail
    //authenticity verification
    if(compare_hmac_SHA256(hmac, recv_hmac)){
        //printf("\033[1;32mSIZE is AUTHENTIC\033[0m\n");    
    }
    else{        
        printf("\033[1;31mSIZE IS NOT AUTHENTIC\033[0m\n");
        goto recvCryptoSizeQuit;
    }

//cout << "size: "<<h_len << "\nrecv seq num: " << recv_seqNum << "-->" << sequenceNumber<<"\n";
    sequenceNumber++;

    free(ciphertext);
    free(hmac);
    free(recv_hmac);
    free(decryptedtext);
    free(iv);
    return h_len;

/* error handling */
recvCryptoSizeQuit:        
    free(ciphertext);
    free(hmac);
    free(recv_hmac);
    free(decryptedtext);
    free(iv);
    return 0;
}



int sendCryptoString(int sock, const char* buf){
    unsigned int buf_len = strlen(buf);
    unsigned char* ciphertext = (unsigned char *) malloc(buf_len + 1 + blockSize + hmacSize + sizeof(uint64_t));
    unsigned char* plaintext = (unsigned char*)malloc(buf_len + 1 + hmacSize + sizeof(uint64_t));
    unsigned char* iv = NULL;
    unsigned int plaintext_len, decryptedtext_len, ciphertext_len;
    uint64_t count = htobe64(sequenceNumber + 1);
    int ret;
    //generate the IV at random
    if(!keyGen(iv, blockSize)) 
        goto sendCryptoStringQuit;
    if(!ciphertext || !plaintext)
        goto sendCryptoStringQuit;

    // copy the buffer into plaintext
    strncpy((char*)(plaintext+sizeof(uint64_t)), buf, buf_len); //copy buf
    memcpy(plaintext, &count, sizeof(uint64_t));                //copy seq num
    
    plaintext_len = sizeof(uint64_t) + buf_len + hmacSize;

    // compute hmac of the string (except null terminator) 
    ret = hmac_SHA256((char*)plaintext, buf_len + sizeof(uint64_t), key_hmac, plaintext+buf_len + sizeof(uint64_t));
    if(ret != hmacSize)
        goto sendCryptoStringQuit;

    //cout << "STRING'S hmac     : ";
    //printHex(plaintext+buf_len, 32);

    //encrypt string|hmac(string)
    ciphertext_len = encrypt((unsigned char*)plaintext, plaintext_len, key, iv, ciphertext, EVP_aes_256_cbc());
    if(ciphertext_len == -1)
        goto sendCryptoStringQuit;

    //send ciphertext size (secure)
    if(sendCryptoSize(sock, ciphertext_len) == false)
        goto sendCryptoStringQuit;

    //printf("Sending string...\n");
    /*debug */
    plaintext[buf_len] = '\0';
    //printf("\033[1;33m[%uBytes]Plain: \033[31;47m%s\033[0m\n", plaintext_len, (char*)plaintext);   

//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//  _dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // send IV 
    ret = send(sock, iv, blockSize, 0);
    if(ret < 0 || ret != blockSize)
        goto sendCryptoStringQuit;

    // send encrypted string  
    ret = send(sock, ciphertext, ciphertext_len, 0);
    sequenceNumber++;
    if(ret < 0 || ret != ciphertext_len)
        goto sendCryptoStringQuit;
    
    //printf("\tSTRING sent.\n");

    free(ciphertext);
    free(plaintext);
    free(iv);
    return ciphertext_len;

/* error handling */
sendCryptoStringQuit:
    free(ciphertext);
    free(plaintext);
    free(iv);
    perror("ERROR string");
    return -1;

}

int recvCryptoString(int sock, char*& buf){
    unsigned char *ciphertext, *decryptedtext, *hmac, *recv_hmac;
    unsigned char* iv = NULL;
    uint64_t ciphertext_len;
    uint64_t recv_count, recv_seqNum;
    int ret, decryptedtext_len;
    void* r;

    //receive ciphertext size (secure)
    ciphertext_len = recvCryptoSize(sock);
    if(ciphertext_len == 0)
        return -1;
    if(ciphertext_len <= hmacSize || ciphertext_len > 256 + hmacSize){  //if someone change the string size. At least the hmac must exists
        perror("ERROR string\n");
        return -1;
    }
    //printf("Receiving string...\n");

    ciphertext = (unsigned char*)malloc(ciphertext_len);
    decryptedtext = (unsigned char*)malloc(ciphertext_len);
    iv = (unsigned char*)malloc(blockSize);
    if(!ciphertext || !decryptedtext || !iv)
        goto recvCryptoStringQuit_2;

    // receive IV 
    ret = recv(sock, iv, blockSize, MSG_WAITALL);    
    if(ret < 0 || ret != blockSize)   //error || not all bytes received
        goto recvCryptoStringQuit_2;

    //receive the ciphertext
    ret = recv(sock, ciphertext, ciphertext_len, MSG_WAITALL); 
    if(ret < 0 || ret != ciphertext_len)        
        goto recvCryptoStringQuit_2;

//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // Decrypt the ciphertext
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext, EVP_aes_256_cbc());
    if(decryptedtext_len == -1)
        goto recvCryptoStringQuit_2;

    hmac = (unsigned char*)malloc(hmacSize); 
    recv_hmac = (unsigned char*)malloc(hmacSize); 
    if(!hmac || !recv_hmac)
        goto recvCryptoStringQuit_1;
    
    r = memcpy(recv_hmac, decryptedtext + (decryptedtext_len - hmacSize), hmacSize);
    if(r != recv_hmac)
        goto recvCryptoStringQuit_1;
    

    // compute hmac of the string (except null terminator) 
    ret = hmac_SHA256((char*)decryptedtext, (decryptedtext_len - hmacSize), key_hmac, hmac);
    if(ret != hmacSize)
        goto recvCryptoStringQuit_1;

    // Resize and add a NULL terminator. We are expecting printable text
    
    decryptedtext[decryptedtext_len-hmacSize] = '\0';

/*    
    cout << "STRING'S hmac     : ";
    printHex(hmac, hmacSize);
    cout << "STRING'S recv_hmac: ";
    printHex(recv_hmac, hmacSize);
*/  

    /* verify hmac */
    if(compare_hmac_SHA256(hmac, recv_hmac)){
        //printf("\033[1;32mSTRING is AUTHENTIC\033[0m\n");    
    }
    else{        
        printf("\033[1;31mSTRING IS NOT AUTHENTIC\033[0m\n");
        goto recvCryptoStringQuit_1;
    }

    //printf("\033[1;33m[%lu]Decrypted String: \033[31;47m%s\033[0m\n", strlen((char*)decryptedtext), (char*)decryptedtext);
    buf = (char*)malloc(decryptedtext_len - (hmacSize + sizeof(uint64_t)) + 1);
    if(!buf){
        goto recvCryptoStringQuit_1;
    }
    memcpy(buf, decryptedtext+sizeof(uint64_t), decryptedtext_len - sizeof(uint64_t) - hmacSize);
    memcpy(&recv_count, decryptedtext, sizeof(uint64_t));
    buf[decryptedtext_len - hmacSize - sizeof(uint64_t)] = '\0';
    recv_seqNum = be64toh(recv_count);
    if(recv_seqNum != sequenceNumber){
        free(buf);
        goto recvCryptoStringQuit_1;
    }
    sequenceNumber++;

    // no error ending 
    free(decryptedtext);
    free(ciphertext);
    free(hmac);
    free(recv_hmac);
    free(iv);
    return decryptedtext_len;

/* error handling */
recvCryptoStringQuit_1:
    free(hmac);
    free(recv_hmac);
recvCryptoStringQuit_2:
    free(ciphertext);
    free(decryptedtext);
    free(iv);
    perror("ERROR string\n");
    return -1;
    
}



uint64_t sendCryptoFileTo(int sock, const char* fs_name, int &err){    
    FILE *fs = NULL;
    void* r;
    int ret;
    uint64_t count;
    string path = fs_name;

    // Compute file size 
    uint64_t len;
    if(getFileSize(path, len) == false){
        sendCryptoSize(sock, len);
        err = 1;
        return 0;
    }
    
    // Compute number of fragments
    unsigned int nFrags = len / LENGTH;
    if((len % LENGTH)>0)
        nFrags++;
        
    // Send file size 
    if(sendCryptoSize(sock, len) == false)
        return 0;


    unsigned int cipherSize = len + 16 - (len %16);
    
    /*encryption and hmac allocations */
    EVP_CIPHER_CTX *ctx = NULL;
    HMAC_CTX* mdctx = NULL;
    int tmp_len;
    unsigned char* iv = NULL;
    /* malloc all buffers */
    unsigned char* sdbuf = (unsigned char*)malloc(sizeof(uint64_t) + LENGTH + hmacSize); /* blockSize + hmacSize */
    unsigned char* ciphertext = (unsigned char*)malloc(sizeof(uint64_t) + LENGTH + blockSize + hmacSize); 
    unsigned char* hmac = (unsigned char*)malloc(hmacSize);
    if(!sdbuf || !ciphertext || !hmac)
        goto sendCryptoFileToQuit_1;
    //generate the IV at random
    if(!keyGen(iv, blockSize)) 
        goto sendCryptoFileToQuit_1;


// ENCRYPTION init
    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        goto sendCryptoFileToQuit_1;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        goto sendCryptoFileToQuit_1;

// HMAC init
    if(!(mdctx = HMAC_CTX_new()))
        goto sendCryptoFileToQuit_1;
    if(1 != HMAC_Init_ex(mdctx, key_hmac, key_hmac_size, EVP_sha256(), NULL))
        goto sendCryptoFileToQuit_1;



    // send IV 
    ret = send(sock, iv, blockSize, 0);
    if(ret < 0 || ret != blockSize)
        goto sendCryptoFileToQuit_1;

    cout << "Sending file...\n";
    //open the file
    fs = fopen(fs_name, "r");
    if(fs == NULL){
        cout << "ERROR: File not found.\n";   
        goto sendCryptoFileToQuit_1;
    }
    else{
        memset(sdbuf, 0, LENGTH);
        int fs_block_sz, ciphertext_len;
        int blockCount = 0;        
        unsigned int hmac_len;
        //read fragment of file
        while((fs_block_sz = fread(sdbuf+sizeof(uint64_t), sizeof(char), LENGTH, fs)) > 0){
            
            count = htobe64(sequenceNumber);
            memcpy(sdbuf, &count, sizeof(uint64_t));

            // for every fragment update the digest of the plain fragment 
            if(1 != HMAC_Update(mdctx, sdbuf, fs_block_sz+sizeof(uint64_t)))
                goto sendCryptoFileToQuit_1;

            // last fragment, finalize HMAC 
            if(nFrags == (blockCount + 1)){
                if(1 != HMAC_Final(mdctx, hmac, &hmac_len))
                    goto sendCryptoFileToQuit_1;
                // concat hmac to the plain last fragment 
                r = memcpy(sdbuf + sizeof(uint64_t) + fs_block_sz, hmac, hmacSize);
                if((sdbuf+fs_block_sz+sizeof(uint64_t)) != r)
                    goto sendCryptoFileToQuit_1;
                fs_block_sz += hmacSize;
            }

            // encrypt every fragment 
            if(1 != EVP_EncryptUpdate(ctx, ciphertext, &tmp_len, (unsigned char*)sdbuf, fs_block_sz+sizeof(uint64_t) ))
                goto sendCryptoFileToQuit_1;
            ciphertext_len = tmp_len;   
         
            // last fragment, finalize the encryption 
            if(nFrags == (blockCount + 1)){
                if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &tmp_len))
                    goto sendCryptoFileToQuit_1;
                ciphertext_len += tmp_len;
            }

//printf("[%uBytes]ciphertext is:\n", ciphertext_len);
//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
            //cout << "Block #"<< blockCount << "\tsize: " << fs_block_sz<<"+("<<sizeof(uint64_t)<<")="<<fs_block_sz+sizeof(uint64_t) << "-->" << ciphertext_len << "\n";
            // send the encrypted file fragment 
            ret = send(sock, ciphertext, ciphertext_len, 0);
            sequenceNumber++;
            if(ret < 0 || ret != ciphertext_len)
                goto sendCryptoFileToQuit_1;
            blockCount++;
            memset(sdbuf, 0, LENGTH);
        }
        // close file 
        ret = fclose(fs);
        if(ret != 0){
            fs = NULL;
            goto sendCryptoFileToQuit_1;
        }


        // free buffers and contexts 
        free(sdbuf);
        free(ciphertext);
        free(hmac);
        free(iv);
        HMAC_CTX_free(mdctx);
        EVP_CIPHER_CTX_free(ctx);
        cout << "\tFile sent\n";
        //cout << "FILE'S hmac: ";
        //printHex(hmac, hmacSize);
        
        // return file length if ok 
        err = 2;
        return len;  
    }

/* error handling */
sendCryptoFileToQuit_1:
    handleErrors();
    if(fs != NULL)
        fclose(fs);                    
    free(sdbuf);
    free(ciphertext);
    free(hmac);
    free(iv);
    HMAC_CTX_free(mdctx);
    EVP_CIPHER_CTX_free(ctx);
    err = 0;
    return 0;
}


//recv file with known length
uint64_t recvCryptoFileFrom(int sock, const char* fr_name, const char* dir_name, int &err){    
    FILE *fr = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int tmp_len, ret;
    uint64_t recv_count, recv_seqNum;
    HMAC_CTX* mdctx = NULL;

    // path strings to handle hmac verification 
    string tmp_path (dir_name);
    tmp_path = tmp_path + "/.tmp/" + fr_name;
    string perm_path (dir_name);
    perm_path = perm_path + "/" + fr_name;

    // receive file length 
    uint64_t size = recvCryptoSize(sock);
    if(size == 0){
        cout << "ERROR: File not found.\n";        
        err = 1;
        return 0;
    }
    //printf("Plain size: %lu\n", size);
    unsigned int nFrags = size / LENGTH;
    if((size % LENGTH) != 0)
        nFrags++;
    //printf("Expected fragments: %u\n", nFrags);
    // size is the plainfile size 

    // remaining represent the amount of ciphertext that i still have to receive
    unsigned int remaining = size + nFrags*sizeof(uint64_t);
    // add reserved space for the hmac
    remaining += hmacSize;
    // padding block 
    remaining += blockSize - (remaining % blockSize);
    
    //remaining = remaining + hmacSize + blockSize - (size % blockSize);
    //printf("Expected ciphertext len: %u\n", remaining);

    char* recvbuf = (char*)malloc(sizeof(uint64_t) + LENGTH + blockSize + hmacSize); 
    unsigned char* plaintext = (unsigned char*)malloc(sizeof(uint64_t) + LENGTH + blockSize + hmacSize);
    unsigned char* recv_hmac = (unsigned char*)malloc(hmacSize);
    unsigned char* hmac = (unsigned char*)malloc(hmacSize); 
    unsigned char* iv = (unsigned char*)malloc(blockSize);       
    if(!recvbuf || !plaintext || !recv_hmac || !hmac || !iv)
        goto recvCryptoFileFromQuit_1;

    // receive IV 
    ret = recv(sock, iv, blockSize, MSG_WAITALL);    
    if(ret < 0 || ret != blockSize)   //error || not all bytes received
        goto recvCryptoFileFromQuit_1;

// ENCRYPTION
    // Create and initialize the context 
    if(!(ctx = EVP_CIPHER_CTX_new()))
        goto recvCryptoFileFromQuit_1;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        goto recvCryptoFileFromQuit_1;        

// HMAC
    if(!(mdctx = HMAC_CTX_new()))
        goto recvCryptoFileFromQuit_1;
    if(1 != HMAC_Init_ex(mdctx, key_hmac, hmacSize, EVP_sha256(), NULL))
        goto recvCryptoFileFromQuit_1;

    cout << "Receiving file...\n";
    fr = fopen(tmp_path.c_str(), "w");
    if(fr == NULL){
        printf("File cannot be opened");
        goto recvCryptoFileFromQuit_1;
    }
    else{
        unsigned int blockCount = 0;
        int fr_block_sz = 0; 
        int plaintext_len;
        while(remaining > 0){            
            int write_sz, recv_len;

            if(blockCount == 0 && nFrags != 1 && remaining > LENGTH + sizeof(uint64_t))
            	recv_len = LENGTH + blockSize + sizeof(uint64_t);
            // full fragment byte 
            else if(blockCount < nFrags-1)
                recv_len = LENGTH + sizeof(uint64_t);
            // not full fragment -> last one 
            else   //last block has different size in general, considering also possible padding            
                recv_len = remaining;


            // recv the fragment ciphertext 
            fr_block_sz = recv(sock, recvbuf, recv_len, MSG_WAITALL);
            if(fr_block_sz == -1 || fr_block_sz != recv_len)
                goto recvCryptoFileFromQuit_1;

            // decrypt the fragment 
            if(1 != EVP_DecryptUpdate(ctx, plaintext, &tmp_len, (unsigned char*)recvbuf, fr_block_sz))
                goto recvCryptoFileFromQuit_1;
            plaintext_len = tmp_len;                

            // last fragment -> finalize decryption 
            if(nFrags == (blockCount + 1)){ 
                if(1 != EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &tmp_len))
                    goto recvCryptoFileFromQuit_1;
                plaintext_len += tmp_len;                 
                plaintext_len -= hmacSize;
                void* r = memcpy(recv_hmac, plaintext + plaintext_len, hmacSize);
                if(recv_hmac != r)
                    goto recvCryptoFileFromQuit_1;
            }
            memcpy(&recv_count, plaintext, sizeof(uint64_t));
            recv_seqNum = be64toh(recv_count);
            if(recv_seqNum != sequenceNumber){
            	goto recvCryptoFileFromQuit_1;
            }

            //cout << "Block #"<< blockCount <<"\tremaining "<<remaining <<"\trecv: " << fr_block_sz << " Bytes\tSeq: " << recv_seqNum << "\n";   

//printf("[%uBytes]ciphertext is:\n", fr_block_sz);
//BIO_dump_fp (stdout, (const char *)recvbuf, fr_block_sz);

            // update the digest of plaintext fragment
            if(1 != HMAC_Update(mdctx, plaintext, plaintext_len))
                goto recvCryptoFileFromQuit_1;

            // write to file the just decrypted fragment
            write_sz = fwrite(plaintext+sizeof(uint64_t), sizeof(char), plaintext_len- sizeof(uint64_t), fr);                
            if(write_sz != plaintext_len-sizeof(uint64_t))
                goto recvCryptoFileFromQuit_1;

            remaining -= fr_block_sz;
            blockCount++;
            sequenceNumber++;
        }

        // finalize hmac 
        unsigned int hmac_len;     
        if(1 != HMAC_Final(mdctx, hmac, &hmac_len))
            goto recvCryptoFileFromQuit_1;

        // debug print both hmac 
        /*
    cout << "FILE'S hmac:      ";
    printHex(hmac, hmacSize);
    cout <<"FILE'S recv_hmac: ";
    printHex(recv_hmac, hmacSize);
        */

        // equal hmac -> authentic 
        if(compare_hmac_SHA256(hmac, recv_hmac)){
            cout << "\033[1;32mFILE IS AUTHENTIC\033[0m\n";
            string cmd = "mv ";
            cmd = cmd + dir_name + "/.tmp/" + fr_name + " " + dir_name + "/";
            //move the file from temporary directory to permanent
            system(cmd.c_str());
        }
        else{
            cout << "\033[1;31mFILE IS NOT AUTHENTIC\n";
            string cmd = "rm ";
            cmd = cmd + dir_name + "/.tmp/" + fr_name;
            //remove the file
            system(cmd.c_str());
            cout << "\tFILE DELETED.\033[0m\n";
            goto recvCryptoFileFromQuit_1;
        }

        // free memory and contexts
        free(plaintext);
        free(recvbuf);
        free(recv_hmac);                
        free(hmac);
        HMAC_CTX_free(mdctx);
        EVP_CIPHER_CTX_free(ctx);  
        /* close file */
        int ret = fclose(fr);
        if(ret != 0){
            perror("Could not close the file.\n");
        }
        err = 2;
        return size; 
    }

/* error handling */
recvCryptoFileFromQuit_1:
    if(fr != NULL)
        fclose(fr);
    free(recvbuf);
    free(plaintext);
    free(recv_hmac);
    free(hmac);
    free(iv);
    HMAC_CTX_free(mdctx);
    EVP_CIPHER_CTX_free(ctx); 
    system((string("rm ") + tmp_path).c_str());
    handleErrors();
    err = 0;
    return 0;
}

