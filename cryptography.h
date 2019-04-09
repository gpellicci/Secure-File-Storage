#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string.h>

void handleErrors(void)
{
	// perror();
  printf("Error crypto\n");
  exit(1);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


void message_digest_SHA256(const unsigned char *message, size_t message_len, unsigned char*& digest)
{
  EVP_MD_CTX *mdctx;

  if((mdctx = EVP_MD_CTX_create()) == NULL)
    handleErrors();

  if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    handleErrors();

  if(1 != EVP_DigestUpdate(mdctx, message, message_len))
    handleErrors();

  if((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
    handleErrors();

  unsigned int digest_len;
  if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
    handleErrors();

  EVP_MD_CTX_destroy(mdctx);
}


void hmac_SHA256(unsigned char* msg, unsigned int len, unsigned char* key_hmac, unsigned char*& hash_buf){
  //create key
  size_t key_hmac_size = sizeof(key_hmac);
  //declaring the hash function we want to use
  const EVP_MD* md = EVP_sha256();
  int hash_size; //size of the digest
  hash_size = EVP_MD_size(md);
  //create a buffer for our digest
  hash_buf = (unsigned char*)malloc(hash_size); 

	/*
		TODO
		if(!hash_buf){
			perror();
			return;
		}
	*/
  //create message digest context
  HMAC_CTX* mdctx;
  mdctx = HMAC_CTX_new();
	/*
		TODO
		if(!mdctx){
			perror();
			return;
		}
	*/
  //Init,Update,Finalise digest 
  // TODO??
  HMAC_Init_ex(mdctx, key_hmac, key_hmac_size, md, NULL);
  HMAC_Update(mdctx, (unsigned char*) msg, len);
  HMAC_Final(mdctx, hash_buf, (unsigned int*) &hash_size);
  //Delete context
  HMAC_CTX_free(mdctx);
  
  
  printf("Digest is:\n");
  for(int n=0;n<hash_size; n++){
    printf("%02x", (unsigned char) hash_buf[n]);
  }
  printf("\n");
}

bool compare_hmac_SHA256(unsigned char* myDigest, unsigned char* recvDigest){
  int hash_size = EVP_MD_size(EVP_sha256());
  int ret = CRYPTO_memcmp(myDigest, recvDigest, hash_size);
  if(ret != 0)
    return false;
  else
    return true;
}