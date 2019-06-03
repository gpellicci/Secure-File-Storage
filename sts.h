//STATION TO STATION KEY EXCHANGE PROTOCOL
#include <openssl/bn.h>
#include <openssl/dh.h>

static DH *get_dh3072(void);
uint16_t sendBuf(int sock, unsigned char* buf, uint16_t size);
bool sendCertificate(int sock, const char* path);
uint16_t recvBuf(int sock, unsigned char*& buf);
bool confirmIdentity();


//Alice
bool stsInitiator(int sock){
	bool retValue = false;
	int ret, Ya_Yb_size, certB_size, M2_size, symmetricKey_len, keyHash_size, sharedKey_size, Ya_size, Yb_size, M3_signature_len;
	uint64_t count, be;
	unsigned char* encr_count = NULL;
	X509_NAME* subject_name = NULL;
	string path;
	BIGNUM* yb = NULL;
	char* tmpstr = NULL;
	unsigned char* Ya = NULL,* sharedKey = NULL,* keyHash = NULL, *encrKey = NULL, *certB_buf = NULL, *M2 = NULL;
	unsigned char* authKey = NULL, *M2_plain = NULL, *Ya_Yb = NULL, *M3_encrypted = NULL, *M3_signature = NULL, *Yb = NULL;
	char client_subject[] = "/C=IT/O=File Server/CN=File Server";
	FILE* privkey_file = NULL;
	X509* ca_cert = NULL, *certB = NULL;
	X509_CRL* crl = NULL;
	X509_STORE* store = NULL;
	DH* mySession = NULL;
	EVP_PKEY *peer_pub_key = NULL, *privkey = NULL;
	const BIGNUM* pubk = NULL;
	string crl_path;

	printf("------ Station-to-station key exchange ------\n");
	//build store for certificate verification
	string ca_cert_path("clientDir/.certificate/ca_cert.pem");
	if(!readCertificate(ca_cert_path.c_str(), ca_cert)){
		goto fail1;
	}
	crl_path = string("clientDir/.certificate/crl.pem");
	if(!readCrl(crl_path.c_str(), crl)){
		goto fail1;
	}
	if(!buildStore(ca_cert, crl, store)){
		goto fail1;
	}

	//generate a
	//compute Ya
	mySession = get_dh3072();
	if(!mySession){
		goto fail1;
	}
	ret = DH_generate_key(mySession);
	if(ret == 0){
		goto fail1;
	}
	//printf("a gen, Ya gen\n");
	DH_get0_key(mySession, &pubk, NULL);
//send M1: Ya
	Ya = (unsigned char*)malloc(BN_num_bytes(pubk));
	if(!Ya){
		goto fail1;
	}
	ret = BN_bn2bin(pubk, Ya);
	Ya_size = ret;
	if(ret != BN_num_bytes(pubk)){
    	goto fail1;
	}
	ret = sendBuf(sock, Ya, ret);
	if(!ret){
		goto fail1;
	}
	//printf("M1 sent\n");

//recv M2: Yb, {<Ya,Yb>}, certB
	//printf("receiving M2....\n");
	//recv Yb
	ret = recvBuf(sock, Yb);
	if(!ret){
	    goto fail1;
	}
	Yb_size = ret;
	//printf("\treceived Yb\n");
	//compute K
	yb = BN_bin2bn(Yb, Yb_size, NULL);
	sharedKey = (unsigned char*)malloc(DH_size(mySession));
	if(!sharedKey){
    	goto fail1;
	}
	ret = DH_compute_key(sharedKey, yb, mySession);
	if(ret != DH_size(mySession)){
    	goto fail1;
	}
	sharedKey_size = ret;
	//printf("K computed: [%d]\n", sharedKey_size);
	//derive symmetric key pair (encryption and authentication)
	// from the hash of the shared secret
	keyHash_size = EVP_MD_size(EVP_sha512());
	keyHash = (unsigned char*)malloc(keyHash_size);
	if(!keyHash){
    	goto fail1;
	}
	ret = SHA512(sharedKey, sharedKey_size, keyHash);
	if(!ret){
    	goto fail1;
	}
	symmetricKey_len = keyHash_size/2;
	encrKey = (unsigned char*)malloc(symmetricKey_len);
	authKey = (unsigned char*)malloc(symmetricKey_len);
	if(encrKey == 0 || authKey == 0){
    goto fail1;
	}
	memcpy(encrKey, keyHash, symmetricKey_len);
	memcpy(authKey, keyHash + symmetricKey_len, symmetricKey_len);
	memset(sharedKey, 0, sharedKey_size);
	memset(keyHash, 0, keyHash_size);

	//recv {<Ya,Yb>}
	ret = recvBuf(sock, M2);
	if(!ret){
    	goto fail1;
	}
	M2_size = ret;
	int M2_plain_len;
	M2_plain = (unsigned char*)malloc(2*M2_size);
	if(!M2_plain){
    	goto fail1;
	}
	M2_plain_len = decrypt(M2, M2_size, encrKey, NULL, M2_plain, EVP_aes_256_ecb());
	if(M2_plain_len == -1){
    	goto fail1;
	}
	//printf("\treceived M2\n");

	//recv certB
	ret = recvBuf(sock, certB_buf);
	if(!ret){
    	goto fail1;
	}
	certB_size = ret;
	certB = d2i_X509(NULL, (const unsigned char**)&certB_buf, certB_size);
	if(!certB){
    	goto fail1;
	}
	certB_buf -= certB_size;
	//printf("\treceived certB\n");

//check if Yb was authentic
	Ya_Yb_size = Yb_size + Ya_size;
	Ya_Yb = (unsigned char*)malloc(Ya_Yb_size);
	if(!Ya_Yb){
    goto fail1;
	}
	memcpy(Ya_Yb, Ya, Ya_size);
	memcpy(Ya_Yb + Ya_size, Yb, Yb_size);

	//check if valid client
	subject_name = X509_get_subject_name(certB);
	tmpstr = X509_NAME_oneline(subject_name, NULL, 0);
	if(strcmp(client_subject, tmpstr) != 0){		//check if it's the client i want to speak to
		goto fail1;
	}

	//verify certificate
	if(!verifyCertificate(store, certB)){
		printf("Not valid certificate\n");
    	goto fail1;
	}
	//printf("Certificate verification on CA passed\n");

//ask client to confirm server identity
	printf("Server identity:\n");
	printf("Subject: %s\n", tmpstr);
	if(!confirmIdentity()){ //add input for identity confirmation by the user
    	goto fail1;
	}

	//get the peer public key
	peer_pub_key = X509_get_pubkey(certB);
	if(!peer_pub_key){
    	goto fail1;
	}
	//verify the signature Ya_Yb with that signature <Ya,Yb>
	if(!verifySignature(Ya_Yb, Ya_Yb_size, M2_plain, M2_plain_len, peer_pub_key)){
    	goto fail1;
	}
	//printf("M2: Yb authentic\n");

//delete a
	DH_free(mySession);
	mySession = NULL;


//send M3: {<Ya,Yb>}, certA
	//printf("sending M3...\n");
	//send {<Ya,Yb>}
	privkey_file = fopen("clientDir/.certificate/priv_key.pem", "r");
	if(!privkey_file){
		goto fail1;
	}
	privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
	if(!privkey){
		fclose(privkey_file);
		goto fail1;
	}
	fclose(privkey_file);
	M3_signature_len = sign(Ya_Yb, Ya_Yb_size, privkey, M3_signature);
	if(!M3_signature){
	    goto fail1;
	}
	EVP_PKEY_free(privkey);
	privkey = NULL;


	M3_encrypted = (unsigned char*)malloc(M3_signature_len + 16);
	if(!M3_encrypted){
    	goto fail1;
	}
	int M3_encrypted_len;
	M3_encrypted_len = encrypt(M3_signature, M3_signature_len, encrKey, NULL, M3_encrypted, EVP_aes_256_ecb());
	if(M3_encrypted_len == -1){
    	goto fail1;
	}
	ret = sendBuf(sock, M3_encrypted, M3_encrypted_len); 
	if(!ret){
		goto fail1;
	}
	//printf("\tm3 sent\n");

	//send certA
	path = string("clientDir/.certificate/cert.pem");
	if(!sendCertificate(sock, path.c_str())){
		goto fail1;
	}
	//printf("\tsent certA\n");



	printf("Session start.\n");
	printf("------\n\n");
	/*
	printf("Encryption key: \n");
	printHex(encrKey, symmetricKey_len);
	printf("Authentication key: \n");
	printHex(authKey, symmetricKey_len);
	printf("------\n");
	*/
	memcpy(key, encrKey, symmetricKey_len);
	memcpy(key_hmac, authKey, symmetricKey_len);

	//session start
	sequenceNumber = 0;
	retValue = true;

fail1:
	if(retValue == false){
		memset(key, 0, 32);
		memset(key_hmac, 0, 32);
	}
	free(Ya_Yb);
	free(M2_plain);
	free(encrKey);
	free(authKey);
	free(keyHash);
	free(sharedKey);
	free(Ya);
	free(Yb);
	free(tmpstr);
	free(certB_buf);
	free(M3_encrypted);
	free(M3_signature);
	free(encr_count);
	X509_free(ca_cert);
	X509_free(certB);
	X509_CRL_free(crl);
	X509_STORE_free(store);
	DH_free(mySession);
	EVP_PKEY_free(peer_pub_key);
	EVP_PKEY_free(privkey);
	return retValue;
}


//Bob
bool stsResponse(int sock){
	bool retValue = false;
	printf("------ Station-to-station key exchange ------\n");
	char client_subject[] = "/C=IT/CN=Client";
	int ret, Ya_size, certA_size, M3_size, M2_signature_len, Ya_Yb_size, Yb_size, symmetricKey_len, keyHash_size, sharedKey_size;
	uint64_t count, be, recv_count;
	unsigned char* encr_count = NULL;
	unsigned char* sharedKey = NULL, * keyHash = NULL, * encrKey = NULL, * authKey = NULL;
	unsigned char* Ya_Yb = NULL, *M2_encrypted = NULL, * M3_plain = NULL, * Yb = NULL, *certA_buf = NULL, *M3 = NULL, *M2_signature = NULL, *Ya = NULL;
	char* tmpstr = NULL;
	EVP_PKEY* peer_pub_key = NULL, *privkey = NULL;
	X509_NAME* subject_name = NULL;
	X509* ca_cert = NULL, *certA = NULL;
	X509_CRL* crl;
	X509_STORE* store;
	FILE* privkey_file = NULL;
	BIGNUM* ya = NULL;
	DH* mySession = NULL;
	//build store for certificate verification
	string ca_cert_path("serverDir/.certificate/ca_cert.pem");
	string crl_path("serverDir/.certificate/crl.pem");
	string path("serverDir/.certificate/cert.pem");
	if(!readCertificate(ca_cert_path.c_str(), ca_cert)){
		goto fail2;
	}
	if(!readCrl(crl_path.c_str(), crl)){
		goto fail2;
	}
	if(!buildStore(ca_cert, crl, store)){
		goto fail2;
	}
	//recv M1: Ya	
	ret = recvBuf(sock, Ya);
	if(!ret){
		goto fail2;
	}
	Ya_size = ret;
	//printf("received Ya\n");

	//generate b, Yb
	mySession = get_dh3072();
	if(!mySession){
			goto fail2;
	}
	ret = DH_generate_key(mySession);
	if(ret == 0){
		goto fail2;	
	}
	//printf("b gen, Yb gen\n");
	const BIGNUM* pubk;
	DH_get0_key(mySession, &pubk, NULL);
	//compute K
	ya = BN_bin2bn(Ya, Ya_size, NULL);
	if(!ya){
		goto fail2;
	}
	sharedKey = (unsigned char*)malloc(50000);//DH_size(mySession));
	if(!sharedKey){
		goto fail2;
	}
	sharedKey_size = DH_compute_key(sharedKey, ya, mySession);
	//printf("K computed: [%d]\n", sharedKey_size);
	// derive symmetric key pair (encryption and authentication) from the
	// hash of the sharedSecret (sha512)
	keyHash_size = EVP_MD_size(EVP_sha512());
	keyHash = (unsigned char*)malloc(keyHash_size);
	if(!keyHash){
		goto fail2;
	}
	ret = SHA512(sharedKey, sharedKey_size, keyHash);
	if(!ret){
		free(keyHash);
		goto fail2;
	}
	symmetricKey_len = keyHash_size/2;
	encrKey = (unsigned char*)malloc(symmetricKey_len);
	authKey = (unsigned char*)malloc(symmetricKey_len);
	if(encrKey == 0 || authKey == 0){
		free(keyHash);
		goto fail2;
	}
	memcpy(encrKey, keyHash, symmetricKey_len);
	memcpy(authKey, keyHash + symmetricKey_len, symmetricKey_len);
	memset(sharedKey, 0, sharedKey_size);
	memset(keyHash, 0, keyHash_size);
	free(keyHash);

//send M2: Yb, {<Ya,Yb>}, certB
	//("sending M2....\n");
	//send Yb
	Yb = (unsigned char*)malloc(BN_num_bytes(pubk));
	if(!Yb){
		goto fail2;
	}
	ret = BN_bn2bin(pubk, Yb);
	Yb_size = ret;
	if(ret != BN_num_bytes(pubk)){
		goto fail2;
	}
	ret = sendBuf(sock, Yb, ret);
	if(!ret){
		goto fail2;
	}
	//printf("\tsent Yb\n");
	//send {<Ya,Yb>}
	Ya_Yb_size = Ya_size + Yb_size;
	Ya_Yb = (unsigned char*)malloc(Ya_Yb_size);
	if(!Ya_Yb){
		goto fail2;
	}
	memcpy(Ya_Yb, Ya, Ya_size);
	memcpy(Ya_Yb + Ya_size, Yb, Yb_size);
	privkey_file = fopen("serverDir/.certificate/priv_key.pem", "r");
	if(!privkey_file){
		goto fail2;
	}
	privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
	if(!privkey){
		goto fail2;
	}
	fclose(privkey_file);
	M2_signature_len = sign(Ya_Yb, Ya_Yb_size, privkey, M2_signature);
	if(!M2_signature){
		goto fail2;
	}
	EVP_PKEY_free(privkey);
	privkey = NULL;
	M2_encrypted = (unsigned char*)malloc(M2_signature_len + 16);
	if(!M2_encrypted){
		goto fail2;
	}
	int M2_encrypted_len;
	M2_encrypted_len = encrypt(M2_signature, M2_signature_len, encrKey, NULL, M2_encrypted, EVP_aes_256_ecb());
	if(M2_encrypted_len == -1){
		goto fail2;
	}
	ret = sendBuf(sock, M2_encrypted, M2_encrypted_len);
	if(!ret){
		goto fail2;
	}
	//printf("\tsent M2\n");

	//send certB
	if(!sendCertificate(sock, path.c_str())){
		goto fail2;
	}
	//printf("\tsent certB\n");

//delete b
	DH_free(mySession);
	mySession = NULL;
	//printf("deleted b\n");
	
//recv M3: {<Ya,Yb>}, certA
	//printf("receiving M3...\n");
	//recv {<Ya,Yb>}
	ret = recvBuf(sock, M3);
	if(!ret){
		goto fail2;
	}
	M3_size = ret;
	int M3_plain_len;
	M3_plain = (unsigned char*)malloc(M2_encrypted_len);
	if(!M3_plain){
		goto fail2;
	}
	M3_plain_len = decrypt(M3, M3_size, encrKey, NULL, M3_plain, EVP_aes_256_ecb());
	if(M3_plain_len == -1){
		goto fail2;
	}
	//printf("\treceived M3\n");

	//recv certA
	ret = recvBuf(sock, certA_buf);
	if(!ret){
		goto fail2;
	}
	certA_size = ret;
	certA = d2i_X509(NULL, (const unsigned char**)&certA_buf, certA_size);
	if(!certA){
		goto fail2;
	}
	certA_buf -= certA_size;
	//printf("\treceived certA\n");

	//verify certificate
	if(!verifyCertificate(store, certA)){
		printf("Not valid certificate\n");
	}
	//printf("Certificate verification on CA passed\n");

	printf("Client identity:\n");
	subject_name = X509_get_subject_name(certA);
	tmpstr = X509_NAME_oneline(subject_name, NULL, 0);
	printf("Subject: %s\n", tmpstr);
	if(strcmp(client_subject, tmpstr) != 0){		//check if it's the client i want to speak to
		goto fail2;
	}

	peer_pub_key = X509_get_pubkey(certA);
	if(!peer_pub_key){
		goto fail2;
	}
	//verify the signature Ya_Yb with that signature <Ya,Yb>
	if(!verifySignature(Ya_Yb, Ya_Yb_size, M3_plain, M3_plain_len, peer_pub_key)){
		goto fail2;
	}
	//printf("M3: Ya is authentic\n");
	printf("Session start.\n");
	printf("------\n");
/*	
	printf("Encryption key: \n");
	printHex(encrKey, symmetricKey_len);
	printf("Authentication key: \n");
	printHex(authKey, symmetricKey_len);
	printf("------\n");
*/
	memcpy(key, encrKey, symmetricKey_len);
	memcpy(key_hmac, authKey, symmetricKey_len);


	sequenceNumber = 0;
	//session start
	retValue = true;

fail2:
	free(sharedKey);
	free(encrKey);
	free(authKey); 
	free(Ya_Yb);
	free(M2_encrypted);	
	free(M3_plain);
	free(Ya);
	free(Yb);
	free(certA_buf);
	free(M3);
	free(M2_signature);
	free(tmpstr);
	free(encr_count);
	EVP_PKEY_free(peer_pub_key);
	EVP_PKEY_free(privkey);
	X509_free(ca_cert);
	X509_free(certA);
	X509_CRL_free(crl);
	X509_STORE_free(store);
	BN_free(ya);
	DH_free(mySession);
	return retValue;	
}



static DH *get_dh3072(void)
{
    static unsigned char dhp_3072[] = {
        0xCC, 0x8A, 0x1F, 0xED, 0xD8, 0xB8, 0xE5, 0x8B, 0xF1, 0xF9,
        0x69, 0xE2, 0x75, 0x04, 0x27, 0x10, 0xBE, 0x71, 0xE7, 0x3B,
        0xE9, 0x63, 0xE4, 0xB0, 0xE6, 0xC4, 0xD8, 0xFC, 0x36, 0x83,
        0x0F, 0x4B, 0xB9, 0xE6, 0x4B, 0x4A, 0x86, 0x00, 0x98, 0x9A,
        0xA3, 0x26, 0x35, 0xA1, 0x59, 0x49, 0x06, 0x4E, 0x52, 0x6C,
        0x89, 0x0B, 0xAF, 0x7F, 0xC1, 0x2C, 0x00, 0xC2, 0xB8, 0xAC,
        0xDD, 0xA1, 0x91, 0x6D, 0x24, 0x1F, 0xCD, 0x0C, 0x6C, 0x5B,
        0x03, 0x90, 0x5F, 0xD2, 0x4E, 0x07, 0x7C, 0x96, 0x4C, 0x65,
        0x2C, 0x40, 0x0A, 0xCF, 0xD0, 0xBE, 0x6E, 0xAC, 0x5A, 0x67,
        0x63, 0x31, 0x2E, 0xBD, 0x5B, 0xF3, 0x42, 0x0B, 0x36, 0x56,
        0xEA, 0x63, 0x28, 0x0C, 0xAD, 0x85, 0x4C, 0x89, 0xF2, 0xA2,
        0x9E, 0xD3, 0xE3, 0x26, 0x69, 0x8B, 0x48, 0x1B, 0xA4, 0xC4,
        0xEA, 0x9E, 0xB5, 0x65, 0xD5, 0x9D, 0xF0, 0x11, 0xC6, 0x4C,
        0x86, 0x4A, 0x2B, 0xB1, 0x74, 0xCE, 0xCB, 0xDA, 0x36, 0x80,
        0x2B, 0xD6, 0x87, 0x54, 0x6E, 0xD2, 0xD1, 0xEB, 0x68, 0xA8,
        0xFE, 0x3E, 0x51, 0xBE, 0xD6, 0x4F, 0xCD, 0x44, 0xFC, 0xC9,
        0xEE, 0x0D, 0x44, 0xF8, 0xC4, 0x2C, 0xDD, 0xE9, 0x83, 0xC5,
        0xA6, 0x87, 0x69, 0x54, 0x96, 0x7E, 0xC7, 0xD5, 0x08, 0xEC,
        0xF1, 0x87, 0x5F, 0xCC, 0x3F, 0x39, 0xF0, 0xDC, 0xA6, 0x8B,
        0x79, 0x8B, 0xF9, 0xD9, 0x25, 0xA1, 0x52, 0xCF, 0xB4, 0x74,
        0x46, 0x48, 0x55, 0x5C, 0xFC, 0x78, 0xC6, 0x06, 0xA2, 0x79,
        0xC7, 0xB7, 0x6A, 0x47, 0x89, 0xAC, 0xE5, 0x7C, 0x7F, 0x04,
        0xEE, 0x24, 0x92, 0x52, 0xBE, 0x8E, 0xCE, 0x91, 0x97, 0x7F,
        0xB9, 0xC4, 0x93, 0xB9, 0x1D, 0x2C, 0x9D, 0xF7, 0xE6, 0x38,
        0xBA, 0x03, 0x1F, 0x7C, 0xB7, 0x9F, 0x50, 0x00, 0xDF, 0x96,
        0xAF, 0xBE, 0x13, 0x96, 0x0C, 0x96, 0x3A, 0x73, 0xC4, 0x65,
        0x9E, 0xC4, 0x70, 0xE7, 0xD7, 0x8A, 0xEA, 0x63, 0x71, 0xCF,
        0x03, 0x8A, 0x07, 0x86, 0x72, 0x5A, 0x62, 0x49, 0x77, 0xEA,
        0xAE, 0xF4, 0x05, 0x20, 0x45, 0xE7, 0x9C, 0xE2, 0x15, 0xA7,
        0xA2, 0x4F, 0xD0, 0x65, 0x1C, 0xEB, 0xBB, 0xA5, 0x0E, 0x06,
        0x68, 0xE2, 0x79, 0x2C, 0xC2, 0xC8, 0xCF, 0x6D, 0x2C, 0x88,
        0xF0, 0x6E, 0x76, 0x6B, 0xC8, 0xE0, 0x54, 0x4A, 0xF9, 0xE0,
        0x86, 0x07, 0x6B, 0x75, 0x6B, 0x23, 0xBB, 0xDE, 0xAF, 0x7D,
        0x82, 0x7E, 0x8C, 0xA4, 0xBA, 0xF4, 0x86, 0xC6, 0x06, 0x1F,
        0x36, 0xC2, 0x1A, 0x45, 0xA8, 0xE6, 0xC3, 0x83, 0x39, 0x98,
        0x62, 0xA2, 0x2A, 0xB9, 0x05, 0x87, 0x35, 0xE5, 0x2E, 0x44,
        0xFE, 0xAD, 0x0A, 0xD5, 0x3D, 0x90, 0xD0, 0xF8, 0xF5, 0x78,
        0xF0, 0x40, 0xDE, 0x1E, 0x4C, 0xD0, 0x38, 0xA6, 0x2A, 0x6B,
        0x9F, 0xBB, 0x72, 0x8B
    };
    static unsigned char dhg_3072[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_3072, sizeof(dhp_3072), NULL);
    g = BN_bin2bn(dhg_3072, sizeof(dhg_3072), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}


uint16_t sendBuf(int sock, unsigned char* buf, uint16_t size){
	int ret = send(sock, &size, sizeof(uint16_t), 0);
	if(ret != sizeof(uint16_t)){
		return 0;
	}
	ret = send(sock, buf, size, 0);
	if(ret != size){
		return 0;
	}
	return size;
}

//send cert
bool sendCertificate(int sock, const char* path){
	X509* cert;
	FILE* cert_file = fopen(path, "r");
	if(!cert_file)
		return false;
	cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	fclose(cert_file);
	if(!cert)
		return false;
	unsigned char* cert_buf = NULL;
	int cert_size = i2d_X509(cert, &cert_buf);
	if(cert_size < 0)
		return false;
	int ret = sendBuf(sock, cert_buf, cert_size);
	free(cert_buf);
	OPENSSL_free(cert_buf);
	if(ret == 0)
		return false;
	return true;
}

uint16_t recvBuf(int sock, unsigned char*& buf){
	uint16_t size;
	int ret = recv(sock, &size, sizeof(uint16_t), MSG_WAITALL);
	if(ret != sizeof(uint16_t))
		return 0;
	
	buf = (unsigned char*)malloc(size);
	ret = recv(sock, buf, size, MSG_WAITALL);
	if(ret != size)
		return 0;
	
	return size;

}

bool confirmIdentity(){
	bool confirm = false;
	bool decision = false;
	printf("The certificate is valid and the identity of the server confirmed.\n");
	while(!confirm){
		printf("\nDo you want to continue? y/n\n");
		string s;
		cin >> s;
		if(strcmp(s.c_str(), "y") == 0){
			decision = confirm = true;
		}
		else if(strcmp(s.c_str(), "n") == 0){
			confirm = true;
		}
	}

	if(decision)
		printf("\033[1;32mIdentity confirmed\033[0m\n");
	else
		printf("\033[1;31mIdentity denied\n\033[0m");

	return decision;
}
