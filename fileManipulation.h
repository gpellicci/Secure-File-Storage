unsigned int getFileSize( std::string path ){
	// get the file stream
	FILE* pFile = fopen( path.c_str(), "rb" );
	if(pFile == NULL)
		return 0;
	// set the file pointer to end of file
	fseek( pFile, 0, SEEK_END );

	// get the file size
	unsigned int size = ftell( pFile );

	// return the file pointer to begin of file if you want to read it
	// rewind( pFile );

	// close stream and release buffer
	fclose( pFile );

	return size;
}