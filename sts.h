//STATION TO STATION KEY EXCHANGE PROTOCOL
#include <openssl/bn.h>
#include <openssl/dh.h>

static DH *get_dh2048(void);
uint32_t sendBuf(int sock, unsigned char* buf, uint32_t size);
bool sendCertificate(int sock, const char* path);
uint32_t recvBuf(int sock, unsigned char*& buf);



//Alice
void stsInitiator(int sock){
	printf("------ Station-to-station key exchange ------\n");
	int ret;
	//generate a
	//compute Ya
	DH* mySession = get_dh2048();
	if(!mySession){

	}
	ret = DH_generate_key(mySession);
	if(ret == 0){

	}
	printf("a gen, Ya gen\n");
	const BIGNUM* pubk;
	DH_get0_key(mySession, &pubk, NULL);
//send M1: Ya
	unsigned char* Ya = (unsigned char*)malloc(BN_num_bytes(pubk));
	ret = BN_bn2bin(pubk, Ya);
	int Ya_size = ret;
	if(ret != BN_num_bytes(pubk)){

	}
	sendBuf(sock, Ya, ret);
	printf("M1 sent\n");

//recv M2: Yb, {<Ya,Yb>}, certB
	printf("receiving M2....\n");
	//recv Yb
	unsigned char* Yb = NULL;
	ret = recvBuf(sock, Yb);
	if(!ret){

	}
	int Yb_size = ret;
	printf("\treceived Yb\n");
	//compute K
	BIGNUM* yb = BN_bin2bn(Yb, Yb_size, NULL);
	unsigned char* sharedKey = (unsigned char*)malloc(DH_size(mySession));
	ret = DH_compute_key(sharedKey, yb, mySession);
	if(ret != DH_size(mySession)){

	}
	int sharedKey_size = ret;
	printf("K computed: [%d]\n", sharedKey_size);
	//derive symmetric key pair (encryption and authentication)
	// from the hash of the shared secret
	unsigned int keyHash_size = EVP_MD_size(EVP_sha512());
	unsigned char* keyHash = (unsigned char*)malloc(keyHash_size);
	if(!keyHash){

	}
	ret = SHA512(sharedKey, sharedKey_size, keyHash);
	if(!ret){

	}
	int symmetricKey_len = keyHash_size/2;
	unsigned char* encrKey = (unsigned char*)malloc(symmetricKey_len);
	memcpy(encrKey, keyHash, symmetricKey_len);
	unsigned char* authKey = (unsigned char*)malloc(symmetricKey_len);
	memcpy(authKey, keyHash + symmetricKey_len, symmetricKey_len);
	memset(sharedKey, 0, sharedKey_size);
	memset(keyHash, 0, keyHash_size);

	//recv {<Ya,Yb>}
	unsigned char* M2 = NULL;
	ret = recvBuf(sock, M2);
	if(!ret){

	}
	int M2_size = ret;
	int M2_plain_len;
	unsigned char* M2_plain = (unsigned char*)malloc(2*M2_size);
	M2_plain_len = decrypt(M2, M2_size, encrKey, NULL, M2_plain, EVP_aes_256_ecb());
	if(M2_plain_len == -1){

	}
	printf("\treceived M2\n");

	//recv certB
	unsigned char* certB_buf = NULL;
	ret = recvBuf(sock, certB_buf);
	if(!ret){

	}
	int certB_size = ret;
	X509* certB = d2i_X509(NULL, (const unsigned char**)&certB_buf, certB_size);
	if(!certB){

	}
	printf("\treceived certB\n");

//check if Yb was authentic
	int Ya_Yb_size = Yb_size + Ya_size;
	unsigned char* Ya_Yb = (unsigned char*)malloc(Ya_Yb_size);
	memcpy(Ya_Yb, Ya, Ya_size);
	memcpy(Ya_Yb + Ya_size, Yb, Yb_size);

	//verify certificate TODOOOO

	//verify certificate TODOOOO	

	//get the peer public key
	EVP_PKEY* peer_pub_key = X509_get_pubkey(certB);
	if(!peer_pub_key){

	}
	//verify the signature Ya_Yb with that signature <Ya,Yb>
	if(!verifySignature(Ya_Yb, Ya_Yb_size, M2_plain, M2_plain_len, peer_pub_key)){
		//not auth
	}
	printf("M2: Yb authentic\n");

//delete a
	DH_free(mySession);
	printf("deleted a\n");





//send M3: {<Ya,Yb>}, certA
	printf("sending M3...\n");
	//send {<Ya,Yb>}
	FILE* privkey_file = fopen("clientDir/.certificate/priv_key.pem", "r");
	if(!privkey_file){

	}
	EVP_PKEY* privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
	if(!privkey){

	}
	fclose(privkey_file);
	unsigned char* M3_signature = NULL;
	int M3_signature_len = sign(Ya_Yb, Ya_Yb_size, privkey, M3_signature);
	if(!M3_signature){

	}
	EVP_PKEY_free(privkey);


	unsigned char* M3_encrypted = (unsigned char*)malloc(M3_signature_len + 16);
	int M3_encrypted_len;
	M3_encrypted_len = encrypt(M3_signature, M3_signature_len, encrKey, NULL, M3_encrypted, EVP_aes_256_ecb());
	if(M3_encrypted_len == -1){

	}
	sendBuf(sock, M3_encrypted, M3_encrypted_len);
	printf("\tm3 sent\n");

	//send certA
	string path("clientDir/.certificate/cert.pem");
	sendCertificate(sock, path.c_str());
	printf("\tsent certA\n");



	printf("Session start.\n");
	printf("------\n");
	printf("Encryption key: \n");
	printHex(encrKey, symmetricKey_len);
	printf("Authentication key: \n");
	printHex(authKey, symmetricKey_len);
	printf("------\n");

	memcpy(key, encrKey, symmetricKey_len);
	memcpy(key_hmac, authKey, symmetricKey_len);
	//session start

}

//Bob
void stsResponse(int sock){
	printf("------ Station-to-station key exchange ------\n");

	int ret;
	//recv M1: Ya	
	unsigned char* Ya = NULL;
	ret = recvBuf(sock, Ya);
	if(!ret){

	}
	int Ya_size = ret;
	printf("received Ya\n");

	//generate b, Yb
	DH* mySession = get_dh2048();
	if(!mySession){

	}
	ret = DH_generate_key(mySession);
	if(ret == 0){

	}
	printf("b gen, Yb gen\n");
	const BIGNUM* pubk;
	DH_get0_key(mySession, &pubk, NULL);
	//compute K
	BIGNUM* ya = BN_bin2bn(Ya, Ya_size, NULL);
	if(!ya){
		printf("error\n");
	}
	unsigned char* sharedKey = (unsigned char*)malloc(50000);//DH_size(mySession));
	int sharedKey_size = DH_compute_key(sharedKey, ya, mySession);
	printf("K computed: [%d]\n", sharedKey_size);
	// derive symmetric key pair (encryption and authentication) from the
	// hash of the sharedSecret (sha512)
	unsigned int keyHash_size = EVP_MD_size(EVP_sha512());
	unsigned char* keyHash = (unsigned char*)malloc(keyHash_size);
	if(!keyHash){

	}
	ret = SHA512(sharedKey, sharedKey_size, keyHash);
	if(!ret){

	}
	int symmetricKey_len = keyHash_size/2;
	unsigned char* encrKey = (unsigned char*)malloc(symmetricKey_len);
	memcpy(encrKey, keyHash, symmetricKey_len);
	unsigned char* authKey = (unsigned char*)malloc(symmetricKey_len);
	memcpy(authKey, keyHash + symmetricKey_len, symmetricKey_len);
	memset(sharedKey, 0, sharedKey_size);
	memset(keyHash, 0, keyHash_size);

//send M2: Yb, {<Ya,Yb>}, certB
	printf("sending M2....\n");
	//send Yb
	unsigned char* Yb = (unsigned char*)malloc(BN_num_bytes(pubk));
	ret = BN_bn2bin(pubk, Yb);
	int Yb_size = ret;
	if(ret != BN_num_bytes(pubk)){

	}
	sendBuf(sock, Yb, ret);
	printf("\tsent Yb\n");
	//send {<Ya,Yb>}
	int Ya_Yb_size = Ya_size + Yb_size;
	unsigned char* Ya_Yb = (unsigned char*)malloc(Ya_Yb_size);
	memcpy(Ya_Yb, Ya, Ya_size);
	memcpy(Ya_Yb + Ya_size, Yb, Yb_size);
	FILE* privkey_file = fopen("serverDir/.certificate/priv_key.pem", "r");
	if(!privkey_file){

	}
	EVP_PKEY* privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
	if(!privkey){

	}
	fclose(privkey_file);
	unsigned char* M2_signature = NULL;
	int M2_signature_len = sign(Ya_Yb, Ya_Yb_size, privkey, M2_signature);
	if(!M2_signature){

	}
	EVP_PKEY_free(privkey);
	unsigned char* M2_encrypted = (unsigned char*)malloc(M2_signature_len + 16);
	int M2_encrypted_len;
	M2_encrypted_len = encrypt(M2_signature, M2_signature_len, encrKey, NULL, M2_encrypted, EVP_aes_256_ecb());
	if(M2_encrypted_len == -1){

	}
	sendBuf(sock, M2_encrypted, M2_encrypted_len);
	printf("\tsent M2\n");

	//send certB
	string path("serverDir/.certificate/cert.pem");
	sendCertificate(sock, path.c_str());
	printf("\tsent certB\n");

//delete b
	DH_free(mySession);
	printf("deleted b\n");
	
//recv M3: {<Ya,Yb>}, certA
	printf("receiving M3...\n");
	//recv {<Ya,Yb>}
	unsigned char* M3 = NULL;
	ret = recvBuf(sock, M3);
	if(!ret){

	}
	int M3_size = ret;
	int M3_plain_len;
	unsigned char* M3_plain = (unsigned char*)malloc(M2_encrypted_len);
	M3_plain_len = decrypt(M3, M3_size, encrKey, NULL, M3_plain, EVP_aes_256_ecb());
	if(M3_plain_len == -1){

	}
	printf("\treceived M3\n");

	//recv certA
	unsigned char* certA_buf = NULL;
	ret = recvBuf(sock, certA_buf);
	if(!ret){

	}
	int certA_size = ret;
	X509* certA = d2i_X509(NULL, (const unsigned char**)&certA_buf, certA_size);
	if(!certA){

	}
	printf("\treceived certA\n");

	//verify certificate TODOOOO

	//verify certificate TODOOOO

	EVP_PKEY* peer_pub_key = X509_get_pubkey(certA);
	if(!peer_pub_key){

	}
	//verify the signature Ya_Yb with that signature <Ya,Yb>
	if(!verifySignature(Ya_Yb, Ya_Yb_size, M3_plain, M3_plain_len, peer_pub_key)){

	}
	printf("M3: Ya is authentic\n");
	EVP_PKEY_free(peer_pub_key);
	printf("Session start.\n");
	printf("------\n");
	printf("Encryption key: \n");
	printHex(encrKey, symmetricKey_len);
	printf("Authentication key: \n");
	printHex(authKey, symmetricKey_len);
	printf("------\n");

	memcpy(key, encrKey, symmetricKey_len);
	memcpy(key_hmac, authKey, symmetricKey_len);
	//session start
}



static DH *get_dh2048(void){
    static unsigned char dhp_2048[] = {
        0x81, 0xA1, 0x43, 0xD3, 0x9E, 0xCB, 0xEE, 0x26, 0x13, 0x30,
        0x10, 0x71, 0xA9, 0x8F, 0xB5, 0x93, 0x40, 0xCF, 0xFC, 0x45,
        0x45, 0x5E, 0xBC, 0xE9, 0x82, 0x1E, 0x00, 0x4D, 0x25, 0xF7,
        0x12, 0x33, 0x34, 0xE2, 0x02, 0x8C, 0x67, 0x0B, 0x3A, 0x47,
        0x06, 0x82, 0x78, 0xBC, 0x0E, 0x14, 0x2C, 0xED, 0x16, 0x36,
        0xA6, 0xB0, 0x45, 0x5C, 0x81, 0x26, 0xB4, 0xFF, 0x30, 0x46,
        0x6F, 0x44, 0x84, 0x6D, 0x75, 0xF2, 0x79, 0x48, 0xE6, 0x2B,
        0xA8, 0x7B, 0x83, 0xB5, 0x2D, 0x88, 0xA7, 0x61, 0x22, 0xB6,
        0x8F, 0x8D, 0x7A, 0xC8, 0xC6, 0xA4, 0xFF, 0xCA, 0x2A, 0xE4,
        0x58, 0xD3, 0xEB, 0x2E, 0x66, 0x5D, 0x18, 0x5A, 0xCF, 0xB3,
        0xCC, 0x6A, 0xE8, 0xF5, 0xC3, 0x5F, 0xE4, 0x24, 0x9C, 0xEF,
        0xC6, 0xFB, 0x16, 0x82, 0xCC, 0xB6, 0x0C, 0xAC, 0xB7, 0x01,
        0xEB, 0xE7, 0xBE, 0xDB, 0xB5, 0x17, 0x16, 0x1B, 0x04, 0xFB,
        0x6D, 0x6A, 0x58, 0x09, 0xC9, 0xCC, 0x8F, 0x63, 0x89, 0xD2,
        0xC3, 0x16, 0x29, 0xE8, 0xC1, 0x09, 0x41, 0x76, 0x8A, 0x17,
        0x38, 0xD8, 0xE8, 0xEC, 0x05, 0x67, 0x4F, 0x13, 0x15, 0xE8,
        0x7F, 0x19, 0xD0, 0xE7, 0xEC, 0xB9, 0xDD, 0xC5, 0x3B, 0xE2,
        0xB7, 0x5A, 0xE7, 0x9B, 0x67, 0x58, 0xC4, 0x36, 0x21, 0xA5,
        0x7C, 0x02, 0xB7, 0xDD, 0x1E, 0xFF, 0x5D, 0x4F, 0x19, 0x04,
        0xAF, 0x5C, 0x9C, 0x76, 0x27, 0x8F, 0xF5, 0x0B, 0x74, 0x45,
        0x9B, 0x80, 0xB7, 0x89, 0x2D, 0x4E, 0x79, 0x9A, 0x7C, 0x62,
        0x47, 0x42, 0xEE, 0x15, 0xC0, 0xD6, 0x2A, 0x60, 0x04, 0xBF,
        0xAB, 0xE6, 0xA7, 0x32, 0xCE, 0x9D, 0x51, 0x8B, 0x9E, 0xF6,
        0x2F, 0x5E, 0xFF, 0x3B, 0x26, 0x7A, 0xC1, 0x45, 0x52, 0x38,
        0xAB, 0x93, 0x5F, 0xD3, 0x5C, 0x65, 0x35, 0xFE, 0x54, 0x8E,
        0xED, 0x34, 0x56, 0x91, 0xA5, 0xDB
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}


uint32_t sendBuf(int sock, unsigned char* buf, uint32_t size){
	int ret = send(sock, &size, sizeof(uint32_t), 0);
	if(ret != sizeof(uint32_t)){
		return 0;
	}
	ret = send(sock, buf, size, 0);
	if(ret != size){
		return 0;
	}
	return size;
}

bool sendCertificate(int sock, const char* path){
	X509* cert;
	FILE* cert_file = fopen(path, "r");
	if(!cert_file)
		return false;
	cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	if(!cert_file)
		return false;
	fclose(cert_file);
	unsigned char* cert_buf = NULL;
	int cert_size = i2d_X509(cert, &cert_buf);
	if(cert_size < 0)
		return false;
	int ret = sendBuf(sock, cert_buf, cert_size);
	OPENSSL_free(cert_buf);
	if(ret == 0)
		return false;
	return true;
}

uint32_t recvBuf(int sock, unsigned char*& buf){
	uint32_t size;
	int ret = recv(sock, &size, sizeof(uint32_t), MSG_WAITALL);
	if(ret != sizeof(uint32_t))
		return 0;
	
	buf = (unsigned char*)malloc(size);
	ret = recv(sock, buf, size, MSG_WAITALL);
	if(ret != size)
		return 0;
	
	return size;

}
