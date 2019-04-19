using namespace std;

const char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@";


bool checkStrSize(string s, unsigned int max_len){
	if(s.size() > max_len)
		return false;
	return true;
}


bool checkAllowedChars(string myString){
	const char* s = myString.c_str();
	if(s == NULL)
		return false;
	if(strspn(s, ok_chars) < strlen(s)){
		return false;	
	}
	return true;
}


bool checkInputString(string s, unsigned int maxLen){
    if(checkStrSize(s, maxLen) == false){
        cout << "too large cmd\n";
        return false;
    }
    if(checkAllowedChars(s) == false){
        cout << "Characters not allowed\n";
        return false;        
    }
    return true;
}

bool checkUpDownOperation(string s){
	if(strcmp(s.c_str(), "up") == 0 || strcmp(s.c_str(), "down") == 0 )
		return true;
	else
		return false;
}

bool checkRemoteOperation(string s){
	if(checkUpDownOperation(s) || strcmp(s.c_str(), "list") == 0 )
		return true;
	else
		return false;
}