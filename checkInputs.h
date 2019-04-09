using namespace std;

bool checkStrSize(string s, unsigned int max_len){
	if(s.size() > max_len)
		return false;
	return true;
}

const char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@";

bool checkAllowedChars(const char* s){
	if(s == NULL)
		return false;
	if(strspn(s, ok_chars) < strlen(s)){
		return false;	
	}
	return true;
}
