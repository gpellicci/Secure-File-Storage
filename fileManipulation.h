const long long int maxFileSize = (1ULL << 32);

bool getFileSize( std::string path, unsigned int &size){
	//in case of error:
		//size = 0
		//return false;
	size = 0;

	// get the file stream
	FILE* pFile = fopen( path.c_str(), "rb" );
	if(pFile == NULL){
		perror("Could not open the file. Error");
		return false;
	}

	// set the file pointer to end of file
	int ret = fseek( pFile, 0, SEEK_END );
	if(ret < 0){
		perror("Could not seek to the end of the file. Error:\n");
		return false;
	}

	// get the file size	 
	long long int tmp = ftell(pFile);
	if(tmp < 0){
		perror("ftell() Error:");
		return false;
	}

	/* check 4GB costraint */
	if(tmp > maxFileSize){
		printf("too big file. Error:\n");
		return false;
	}

	size = (unsigned int)tmp;

	// close file
	ret = fclose( pFile );
	if(ret != 0){
		perror("Could not close the file. Error:\n");
		size = 0;
		return false;
	}

	return true;
}
