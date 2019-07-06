// bash build.sh
// ./server 1501 5 59 107 127.0.0.1 1500

#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <math.h>
#include <pthread.h>
#include <sys/mman.h>
#include "myCommonStructs.h"		// shared structs for communicating between hosts
#include "RSAfunctions.h"			// everything needed for RSA 

#define ECHOMAX 255     /* Longest string to echo */


void *ThreadMain(void *arg); // Main program of thread 
struct ThreadArgs { 			// struct for thread arguments
	int clntSock;
	int my_e, my_n, d;
	int sock;
	struct sockaddr_in keyManagerServAddr;
	int *num_threads;
};

void DieWithError(char *errorMessage);  /* External error handling function */
void HandleTCPClient(int clntSock, int my_e, int d, int my_n, int km_sock, const struct sockaddr_in *keyManagerServAddr);

int main(int argc, char *argv[])
{
	int sock, TCPsock, clntSock;                        /* Socket */
	struct sockaddr_in brokerServAddr, brokerTCPAddr; /* Local address */
	struct sockaddr_in keyManagerServAddr;    
	struct sockaddr_in clientAddr;
	struct sockaddr_in fromAddr;	/* from: Client address */
	unsigned int cliAddrLen;         /* Length of incoming message */
	char *keyManagerIP;
	char echoBuffer[ECHOMAX];        /* Buffer for echo string */
	unsigned short brokerServPort, brokerTCPPort;     /* Server port */
	unsigned int keyManagerServPort;
	int recvMsgSize;                 /* Size of received message */
	int p, q, r, my_n, my_e, d, their_e, their_n; 	// variables for public key
	int brokerID, brokerPubKey, clientPubKey;
	pthread_t threadID;							/* Thread ID from pthread_create() */
	struct ThreadArgs *threadArgs;	/* Pointer to argument structure for thread */
  const char *hr = "\n----------------------------------------------\n";  // horizontal rule
	int *num_threads; 
	num_threads = mmap(NULL, sizeof(int),PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	(*num_threads) = 0;

	#define MAXPENDING 5

	if (argc != 8)         /* Test for correct number of parameters */
	{
			fprintf(stderr,"Usage:  %s <THIS BROKER's UDP PORT> <THIS BROKER's TCP PORT> <Broker ID> <p> <q> <Key Manager IP> <Key Manager Port> \n", argv[0]);
			exit(1);
	}
    
	brokerServPort = atoi(argv[1]);  /* First arg:  local port */
	brokerTCPPort = atoi(argv[2]);  // TCP port for client connections
	brokerID = atoi(argv[3]);
	p = atoi(argv[4]);   						// p should be prime - used for encryption/decryption
	q = atoi(argv[5]);							// q should be prime - used for encryption/decryption
	keyManagerIP = argv[6];				
	keyManagerServPort = atoi(argv[7]);    


	// Generate public and private keys
	my_n = p*q, r = (p-1)*(q-1);
	my_e = Generate_e(r);
	d = Generate_d(my_e, r);
	brokerPubKey = my_n*1000 + my_e;   // agreed upon method of storage
	
	// Display broker details on startup
	printf("\n\nprincipal ID=%d   public key is n=%d   e=%d  :: stored as > %d\n\n", brokerID, my_n, my_e, brokerPubKey);

	/* Create socket for sending/receiving datagrams */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
			DieWithError("socket() failed");

	/* Create TCP socket for client communication */
	if ((TCPsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
			DieWithError("socket() failed");
	
	
	/* Construct local address structure */
	memset(&brokerServAddr, 0, sizeof(brokerServAddr));   /* Zero out structure */
	brokerServAddr.sin_family = AF_INET;                /* Internet address family */
	brokerServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
	brokerServAddr.sin_port = htons(brokerServPort);      /* Local port */

		/* Construct local address TCP structure */
	memset(&brokerTCPAddr, 0, sizeof(brokerTCPAddr));   /* Zero out structure */
	brokerTCPAddr.sin_family = AF_INET;                /* Internet address family */
	brokerTCPAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
	brokerTCPAddr.sin_port = htons(brokerTCPPort);      /* Local port */

    
	// construct Key Manager server address structure
	memset(&keyManagerServAddr, 0, sizeof(keyManagerServAddr));
	keyManagerServAddr.sin_family = AF_INET;
	keyManagerServAddr.sin_addr.s_addr = inet_addr(keyManagerIP);
	keyManagerServAddr.sin_port = htons(keyManagerServPort);

	/* Bind to the local address */
	if (bind(sock, (struct sockaddr *) &brokerServAddr, sizeof(brokerServAddr)) < 0)
			DieWithError("bind() failed");

	/* Bind TCP socket to the local address */
	if (bind(TCPsock, (struct sockaddr *) &brokerTCPAddr, sizeof(brokerTCPAddr)) < 0)
			DieWithError("bind() failed");
			
	
	// construct request to key manager
	principal_to_key_mesg km_request;
	key_to_principal_mesg km_response;
	memset(&km_request, 0, sizeof(km_request));
	memset(&km_response, 0, sizeof(km_response));
	km_request.request_type = htonl(register_user);
	km_request.principal_id = htonl(brokerID);
	km_request.public_key = htonl(brokerPubKey);
	
	printf("Registering private key with Key Manager.");
	// send request to key manager  :  set public key
	if (sendto(sock, &km_request, sizeof(km_request), 0, (struct sockaddr *)
				&keyManagerServAddr, sizeof(keyManagerServAddr)) != sizeof(km_request))
		DieWithError("sendto() sent a different number of bytes than expected");	


	if (listen(TCPsock, MAXPENDING) < 0)
		DieWithError("listen() failed");

	for (;;) /* Run forever */
	{
		
		/* Block until receive message from a client */
		if ((*num_threads) >= 5) {
			printf("Not accepting any more threads. %d/5 currently connected\n", (*num_threads));
			sleep(1);
		} else {
			// prepare variables for messages between client and broker
			client_broker_mesg request;
			client_broker_mesg response;
			memset(&request, 0, sizeof(request));
			memset (&response, 0, sizeof(response));

			/* Set the size of the in-out parameter */
			cliAddrLen = sizeof(clientAddr);


			if ((clntSock = accept(TCPsock, (struct sockaddr *) &clientAddr, &cliAddrLen)) < 0)
			DieWithError("accept() failed");
		
			// more threads are accepted
			printf("%s", hr); // print horizontal rule
			printf("Handling client IP: %s   port:  %d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));


			// allocate space for thread arguments
			if ((threadArgs = (struct ThreadArgs *) malloc(sizeof(struct ThreadArgs))) == NULL)
				DieWithError("malloc() failed");

			// assign variables to thread arguments
			threadArgs -> clntSock = clntSock;
			threadArgs -> my_e = my_e;
			threadArgs -> d = d;
			threadArgs -> my_n = my_n;
			threadArgs -> sock = sock;
			threadArgs -> keyManagerServAddr = keyManagerServAddr;
			threadArgs -> num_threads = num_threads;

			// create thread to handle client
			if (pthread_create(&threadID, NULL, ThreadMain, (void *) threadArgs) != 0)
				DieWithError("pthead_create() failed");
			printf("with thead %ld\n", (long int) threadID);

		}
	}
	/* NOT REACHED */
}

void *ThreadMain(void *threadArgs) {
	int clntSock;
	int my_e, d, my_n, sock;
	struct sockaddr_in keyManagerServAddr;
	int *num_threads;

	/* Gurentees that thread resources are deallocated upon return */
	pthread_detach(pthread_self());

	/* Extract socket file descriptor from argument */
	clntSock = ((struct ThreadArgs *) threadArgs) -> clntSock;
	my_e = ((struct ThreadArgs *) threadArgs) -> my_e;
	d = ((struct ThreadArgs *) threadArgs) -> d;
	my_n = ((struct ThreadArgs *) threadArgs) -> my_n;
	sock = ((struct ThreadArgs *) threadArgs) -> sock;
	num_threads = ((struct ThreadArgs *) threadArgs) -> num_threads;
	memcpy(&keyManagerServAddr, &((struct ThreadArgs *) threadArgs) -> keyManagerServAddr, sizeof(keyManagerServAddr));

	free(threadArgs);

	printf("\n%d client(s) connected\n", ++(*num_threads));
	printf("clntSock = %d   e: %d  :  d: %d   - n: %d   - sock: %d\n", clntSock, my_e, d, my_n, sock);
	printf("Key Manager IP: %s   port:  %d\n", inet_ntoa(keyManagerServAddr.sin_addr), ntohs(keyManagerServAddr.sin_port));

	HandleTCPClient(clntSock, my_e, d, my_n, sock, &keyManagerServAddr);
	printf("%d client(s) connected\n\n", --(*num_threads));
	return (NULL);
}
