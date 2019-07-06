// encrypt message with given e and n
int Encrypt(int msg, int e, int n){
	int tmp = msg;

	for (int i = 1; i < e; i++)   // for loop necessary for to deal with large numbers
		tmp = fmod(tmp*msg, n);

	return tmp; // return encrypted message
}


// decrypt message with given d and n
int Decrypt(int e_msg, int d, int n){
	int tmp = e_msg;

	for (int i = 1; i < d; i++) // for loop necessary for to deal with large numbers
		tmp = fmod(tmp*e_msg, n);

	return tmp; // return decrypted message
}

// function for greated common devisor - necessary for encryption
int gcd(int a, int b) {    
	if (a == 0 || b == 0) 
		return 0;
	if (a == b)
		return a;	
	if (a > b)
		return gcd(a-b, b);
	return gcd(a, b-a);
}

// generates a small e for encryption using r
int Generate_e(int r){
	int i = 1;
	while (gcd(++i, r) != 1);  
	return i; 
}

// generates a value d for decryption using e and r
int Generate_d(int e, int r){
	int i = 1;
	while (fmod(e*++i, r) != 1);
	return i; 
}
