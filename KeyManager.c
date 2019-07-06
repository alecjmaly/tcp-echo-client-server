// bash build.sh
// ./keymanager 1500

#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include "myCommonStructs.h"

#define ECHOMAX 255     /* Longest string to echo */

void DieWithError(char *errorMessage);  /* External error handling function */

// register a public key
void register_public_key(int id, int key){
	// call update private key - if no key to update, return -1 and enter if statement
	if(update_public_key(id, key) == -1) {
		FILE *fp;
		fp=fopen("public_keys.csv", "a");   // opens file 
		fprintf(fp,"%d,%d\n", id, key);			// appends new line for new public key
		fclose(fp);										
		printf("\nRegistered new key for id %d, public key is %d.\n", id, key);
	}
}

// update public key (if exists)
int update_public_key(int id, int key){
	FILE *fp;
	FILE *NewFile;
	char line[256];
	char* tmp;
	int updated = -1;
	fp=fopen("public_keys.csv", "r"); // current key file
	NewFile=fopen("temp.csv", "a");		// new file to overwrite with new key
	
	// couldn't open files needed
	if(fp == NULL || NewFile == NULL) {		
		printf("Could not open data file.\n");
		return -1;
	}

	// reads file with public keys
	while(fgets(line, sizeof(line), fp)){   // foreach line in file
		tmp = strtok(line, ",");  						// tokenize line
		// found record to edit
		if (strtol(tmp,NULL,10) == id) {			// if token is desired ID to update
			printf("Found principal id# %d, updating to new key: %d\n", id, key);
			fprintf(NewFile,"%d,%d\n", id, key);  // print new key to file
			updated = 1;												// updated = true
		} else {																// else: write to temp file what is at the current location
			fprintf(NewFile, "%s,%s", tmp, strtok(NULL, ","));
		}
	}

	fclose(fp);
	fclose(NewFile);
	remove("public_keys.csv");			// remove old file
	rename("temp.csv", "public_keys.csv");		// replace with updated file (contains new key if it has changed)
	return updated; // 1 = record was found and updated, -1 = no record found/updated		
}

int get_public_key(int id){
	FILE *fp;
	char line[256];
	char* pub_key;
	fp=fopen("public_keys.csv", "r");
	while(fgets(line, sizeof(line), fp)){				// iterates through each line of file
		pub_key = strtok(line, ",");									// tokenizes each line
		if (strtol(pub_key,NULL,10) == id) {					// looks for desired id
			pub_key = strtok(NULL, ",");								// get value of public key
			printf("returns: %d\n", strtol(pub_key,NULL,10));
			return strtol(pub_key,NULL,10);
		}
	
	}
	return -1;			// returns a value of -1 if it couldn't find a valid public key
}

int main(int argc, char *argv[])
{
	int sock;                        /* Socket */
	struct sockaddr_in echoServAddr; /* Local address */
	struct sockaddr_in echoClntAddr; /* Client address */
	unsigned int cliAddrLen;         /* Length of incoming message */
	char echoBuffer[ECHOMAX];        /* Buffer for echo string */
	unsigned short echoServPort;     /* Server port */
	int recvMsgSize;                 /* Size of received message */
	const char *hr = "\n----------------------------------------------\n";  // horizontal rule

	if (argc != 2)         /* Test for correct number of parameters */
	{
			fprintf(stderr,"Usage:  %s <UDP SERVER PORT>\n", argv[0]);
			exit(1);
	}
	
	echoServPort = atoi(argv[1]);  /* First arg:  local port */
	
	/* Create socket for sending/receiving datagrams */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
			DieWithError("socket() failed");
	
	/* Construct local address structure */
	memset(&echoServAddr, 0, sizeof(echoServAddr));   /* Zero out structure */
	echoServAddr.sin_family = AF_INET;                /* Internet address family */
	echoServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
	echoServAddr.sin_port = htons(echoServPort);      /* Local port */


	/* Bind to the local address */
	if (bind(sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
			DieWithError("bind() failed");
	
	/* Initialize structs */
	key_to_principal_mesg response;
	principal_to_key_mesg request;


	for (;;) /* Run forever */
	{
		// zero out structs
    memset(&response, 0, sizeof(response));
		memset(&request, 0, sizeof(request));

		/* Set the size of the in-out parameter */
    cliAddrLen = sizeof(echoClntAddr);
        
		/* Block until receive message from a client */
		if ((recvMsgSize = recvfrom(sock, &request, sizeof(request), 0,
																(struct sockaddr *) &echoClntAddr, &cliAddrLen)) < 0)
				DieWithError("recvfrom() failed");
       
		printf("%s", hr); // print horizontal rule
		printf("Handling client IP: %s   port:  %d\n", inet_ntoa(echoClntAddr.sin_addr), ntohs(echoClntAddr.sin_port));
		printf("\nrequest_type: %s\n", keyManager_request_type[ntohl(request.request_type)]);     // keyManager_request_type from myCommonStructs.h
		printf("principal id: %d\n", ntohl(request.principal_id));
		
		// handle incoming request
		switch (ntohl(request.request_type)){
			case 0: // set key reuqest
				printf("public key is %d\n",  ntohl(request.public_key)); 
				register_public_key(ntohl(request.principal_id), ntohl(request.public_key));
				break;
			case 1: // get public key request
				response.principal_id = request.principal_id;
				response.public_key = htonl(get_public_key(ntohl(request.principal_id)));
				// send recieved datagram back to the cclient
				if (sendto(sock, &response, sizeof(response), 0,
								(struct sockaddr *) &echoClntAddr, sizeof(echoClntAddr)) != sizeof(response))
						DieWithError("sendto() sent a different number of bytes than expected");			
	
				break;
		}	
	}		
    /* NOT REACHED */
}
