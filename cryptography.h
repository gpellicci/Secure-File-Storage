#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string.h>

#include "keygen.h"


void handleErrors(void)
{
  perror("Error crypto\n");
  //exit(1);
}

//todo 4 encrypt / decrypt non sono corrette
//dobbiamo fare update ad ogni ciclo sui blocchi e final solo all'ultimo

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
    return -1;
  }

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){    
    handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
    handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){ 
    handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {    
    handleErrors();
    return -1;
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
    handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
    handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
    handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void SHA256(char* msg, unsigned int len, unsigned char*& digest){

  unsigned int digestLen = 32;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  EVP_DigestInit(ctx, EVP_sha256());
  EVP_DigestUpdate(ctx, (unsigned char*)msg, len);
  EVP_DigestFinal(ctx, digest, &digestLen);
  EVP_MD_CTX_free(ctx);

}


void hmac_SHA256(char* msg, unsigned int len, unsigned char* key_hmac, unsigned char*& hash_buf){
  //create key
  size_t key_hmac_size = 32;
  //declaring the hash function we want to use
  const EVP_MD* md = EVP_sha256();
  int hash_size; //size of the digest
  hash_size = EVP_MD_size(md);

  //create a buffer for our digest
  hash_buf = (unsigned char*)malloc(hash_size); 
	if(!hash_buf){
  		perror("ERRORE:\n");
  		return;
	}
	
  //create message digest context
  HMAC_CTX* mdctx;
  mdctx = HMAC_CTX_new();
	if(!mdctx){
  		perror("ERRORE:\n");
  		return;
	}
	
  //Init,Update,Finalise digest 
  // TODO??
  HMAC_Init_ex(mdctx, key_hmac, key_hmac_size, md, NULL);
  HMAC_Update(mdctx, (unsigned char*) msg, len);
  HMAC_Final(mdctx, hash_buf, (unsigned int*) &hash_size);
  //Delete context
  HMAC_CTX_free(mdctx);
  
  
  /*
  printf("Digest is:\n");
  for(int n=0;n<hash_size; n++){
    printf("%02x", (unsigned char) hash_buf[n]);
  }
  printf("\n");
  */
}

bool compare_hmac_SHA256(unsigned char* myDigest, unsigned char* recvDigest){
  unsigned int hash_size = EVP_MD_size(EVP_sha256());
  
  if( CRYPTO_memcmp(myDigest, recvDigest, hash_size) == 0)
    return true;
  else
    return false;  
}



void fileHmac(const char* fname){
    unsigned char *key_hmac = (unsigned char*)"01234567890123456789012345678912";
    unsigned int key_size = 32;

    HMAC_CTX* mdctx = HMAC_CTX_new();
    HMAC_Init_ex(mdctx, key_hmac, key_size, EVP_sha256(), NULL);

    FILE* fd = fopen(fname, "r");
    int size;
    const int chunk = 512;
    unsigned char* buf = (unsigned char*)malloc(chunk);
    while( (size = fread(buf, sizeof(char), chunk, fd)) > 0){
      HMAC_Update(mdctx, buf, size);
    }

    unsigned char* md = (unsigned char*)malloc(32);
    unsigned int md_len = 0;
    HMAC_Final(mdctx, md, &md_len);
    printf("HMAC: ");
    printHexKey(md, md_len);
}