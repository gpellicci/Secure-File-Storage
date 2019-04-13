#include <openssl/rand.h>

bool keyGenToFile(int len, const char* fname){
	int ret = RAND_poll();
	if(ret == -1){
		perror("RAND_poll. Error");
		return false;
	}

	unsigned char* key = (unsigned char*)malloc(len);
	if(key == NULL){
		perror("Could not allocate memory. Error");
		return false;
	}
	ret = RAND_bytes(key, len);	
	if(ret == -1){
		perror("RAND_bytes. Error");
		return false;
	}

	FILE* fd = fopen(fname, "w");
	if(fd == NULL){
		perror("Could not open the file. Error");
		return false;	
	}
	else{
		int w_len = fwrite(key, sizeof(unsigned char), len, fd);
		if(w_len != len || w_len == -1){
			perror("fwrite. Error");
			return false;
		}
		ret = fclose(fd);
		if(ret == -1){
			perror("fclose. Error");
			return false;
		}

		return true;
	}
}

bool keyGen(unsigned char* &pointer, int len){
	int ret = RAND_poll();
	if(ret == -1){
		perror("RAND_poll. Error");
		return false;
	}

	pointer = (unsigned char*)malloc(len);
	if(pointer == NULL){
		perror("Could not allocate memory. Error");
		return false;
	}
	ret = RAND_bytes(pointer, len);	
	if(ret == -1){
		perror("RAND_bytes. Error");
		return false;
	}

	return true;
}

bool readKeyFromFile(unsigned char* &key, int len, const char* fname){
	unsigned char* tmp = (unsigned char*)malloc(len);
	if(tmp == NULL){
		perror(". Error");
		return false;
	}

	FILE* fd = fopen(fname, "r");
	if(fd == NULL){
		perror("fopen. Error");
		return false;
	}
	else{
		int r_len = fread(tmp, sizeof(unsigned char), len, fd);

		if(r_len != len || r_len == -1){
			perror("fread. Error");
			return false;	
		}

		int ret = fclose(fd);
		if(ret == -1){
			perror("fclose. Error");
			return false;
		}

		key = tmp;
		return true;
	}
}

void printHexKey(unsigned char* key, int len){
	if(key == NULL || len < 0)
		return;

	printf("Key: ");	
	for(int i=0; i<len; i++)
		printf("%02x", key[i]);
	printf("\n");
}