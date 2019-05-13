#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
using namespace std;

bool readCertificate(string filename, X509* &cert){
	FILE* file = fopen(filename.c_str(), "r");
	if(!file)
		return false;
	cert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!cert)
		return false;
	if(fclose(file) != 0)
		return false;
	
	return true;
}

bool readCrl(string filename, X509_CRL* &crl){
	FILE* file = fopen("Papere_crl.pem", "r");
	if(!file)
		return false;
	crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
	if(!crl)
		return false;
	if(fclose(file) != 0)
		return false;

	return true;
}

bool buildStore(X509* ca_cert, X509_CRL* crl, X509_STORE*& store){
	store = X509_STORE_new();
	if( !store )
		return false;
	if( !X509_STORE_add_cert(store, ca_cert) )
		return false;
	if( !X509_STORE_add_crl(store, crl) )
		return false;
	if( !X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) )
		return false;

	return true;
}

bool verifyCertificate(X509_STORE* store, X509* cert){
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	if( !ctx )
		return false;
	if( !X509_STORE_CTX_init(ctx, store, cert, NULL) )
		return false;
	int ret = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);
	if(ret != 1)
		return false;

	return true;
}

void printSubjectName(X509* cert){
	X509_NAME* subject_name = X509_get_subject_name(cert);
	char* tmpstr = X509_NAME_oneline(subject_name, NULL, 0);
	printf("Subject name: %s\n", tmpstr);
	free(subject_name);
	free(tmpstr);	
}

void printIssuerName(X509* cert){
	X509_NAME* issuer_name = X509_get_subject_name(cert);
	char* tmpstr = X509_NAME_oneline(issuer_name, NULL, 0);
	printf("Subject name: %s\n", tmpstr);
	free(issuer_name);
	free(tmpstr);	
}