unsigned int getFileSize( std::string path ){
	// get the file stream
	FILE* pFile = fopen( path.c_str(), "rb" );
	if(pFile == NULL)
		return 0;
	// set the file pointer to end of file
	fseek( pFile, 0, SEEK_END );

	/* 

	TODO 
	int ret = fseek( pFile, 0, SEEK_END );
	if(ret < 0)
		ERRORE!
		perror();
	*/

	// get the file size
	unsigned int size = ftell( pFile );
	/* 

	TODO 
	ret = ftell( pFile );
	if(ret < 0)
		ERRORE!
		perror();
	*/

	// return the file pointer to begin of file if you want to read it
	// rewind( pFile );

	// close stream and release buffer
	fclose( pFile );

	return size;
}
