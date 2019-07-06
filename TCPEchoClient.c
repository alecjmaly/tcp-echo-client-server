// bash build.sh
// ./client 127.0.0.1 1501 5 18 113 31 1500

#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <math.h>
#include "myCommonStructs.h"		// shared structs for communicating between hosts
#include "RSAfunctions.h"			// everything needed for RSA 


#define ECHOMAX 255     /* Longest string to echo */
#define RCVBUFSIZE 32 /* Size of receive buffer */

void DieWithError(char *errorMessage);  /* External error handling function */


int main(int argc, char *argv[])
{
	int sock, TCPsock;                        /* Socket descriptor */
	struct sockaddr_in brokerServAddr; /* Broker server address */
	struct sockaddr_in keyManagerServAddr; // Key Manager server address
	struct sockaddr_in fromAddr;     /* Source address of echo */
	unsigned short brokerPort, keyManagerPort;     /* Echo server port */
	unsigned int fromSize;           /* In-out of address size for recvfrom() */
	char *servIP;                    /* IP address of server */
	char *echoString;                /* String to send to echo server */
	char echoBuffer[ECHOMAX+1];      /* Buffer for receiving echoed string */
	int respStringLen;               /* Length of received response */
	int p, q, r, my_n, my_e, d, their_e, their_n;  // vars for public and private keys
	int clientID, clientPubKey, brokerID, brokerPubKey; // more vars for public and private keys
	int action, transaction_id, num_stocks; // actions for client input
	int totalBytesRcvd, bytesRcvd;
  const char *hr = "\n----------------------------------------------\n";  // horizontal rule


	if ((argc < 7) || (argc > 8))    /* Test for correct number of arguments */
	{
		fprintf(stderr,"Usage: %s <Server/Broker IP> <Broker TCP Port> <Broker ID> <Client ID> <p> <q> [<KeyManager Port>]\n", argv[0]);
			exit(1);
	}


	servIP = argv[1];           /* First arg: server IP address (dotted quad) */
	brokerPort = atoi(argv[2]);       /* Second arg: Server Port */
	brokerID = atoi(argv[3]);			
	clientID = atoi(argv[4]);
	p = atoi(argv[5]);					// p should be prime
	q = atoi(argv[6]);					// q should be prime
	keyManagerPort = atoi(argv[7]);  /* Use given port, if any */
	
	
	// build public key
	my_n = p*q, r = (p-1)*(q-1);
	my_e = Generate_e(r);
	d = Generate_d(my_e, r);		
	clientPubKey = my_n*1000 + my_e;

	// Display client details on startup
	printf("\n\nprincipal ID=%d   public key is n=%d   e=%d  :: stored as > %d\n\n", clientID, my_n, my_e, clientPubKey);


	/* Create a datagram/UDP socket */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
			DieWithError("socket() failed");
	
		/* Create a datagram/TCP socket for Broker Communication */
	if ((TCPsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
			DieWithError("socket() failed");


	/* Construct the broker server address structure */
	memset(&brokerServAddr, 0, sizeof(brokerServAddr));    /* Zero out structure */
	brokerServAddr.sin_family = AF_INET;                 /* Internet addr family */
	brokerServAddr.sin_addr.s_addr = inet_addr(servIP);  /* Server IP address */
	brokerServAddr.sin_port = htons(brokerPort);     /* Server port */

	// Construct the Key Manager server adddress structure
	memset(&keyManagerServAddr, 0, sizeof(keyManagerServAddr));
	keyManagerServAddr.sin_family = AF_INET;
	keyManagerServAddr.sin_addr.s_addr = inet_addr(servIP);
	keyManagerServAddr.sin_port = htons(keyManagerPort);

	// send to Key Manager
	// construct request for setting PK
	principal_to_key_mesg request;
	memset(&request, 0, sizeof(request));
	request.request_type = htonl(register_user);
	request.principal_id = htonl(clientID);
	request.public_key = htonl(clientPubKey);
    

	/* Send request to the Key Manager : register public key*/
	if (sendto(sock, &request, sizeof(request), 0, (struct sockaddr *)
							&keyManagerServAddr, sizeof(keyManagerServAddr)) != sizeof(request))
			DieWithError("sendto() sent a different number of bytes than expected");
	// END send to Key Manager
    
	
	// loop to be inserted here, prompt for broker - overwrite brokerID + reprompt for msg variables
	// functionality added - communicate multiple messages to several different brokers

	do { // loop until valid input 
		printf("Please input an action - (0) to buy (1) to sell: ");
		scanf("%d", &action);
		while (getchar() != '\n');  // clear stdin buffer
	} while (action != 0 && action != 1);
	

	do { // loop until valid input 
		printf("Please input a Transaction ID (must be below n): ");
		scanf("%d", &transaction_id);
		while (getchar() != '\n');  // clear stdin buffer
	} while (transaction_id < 0 || transaction_id >= my_n);

	do { // loop until valid input 
		printf("Please input the number of stocks (must be below n): ");
		scanf("%d", &num_stocks);
		while (getchar() != '\n');  // clear stdin buffer
	} while (num_stocks < 0 || num_stocks >= my_n);


	// Send request to Key Manager (Get Broker Public Key)
	// construct request for getting public key
	principal_to_key_mesg reqest;
	memset(&request, 0, sizeof(request));
	request.request_type = htonl(request_key);
	request.principal_id = htonl(brokerID);
	request.public_key = htonl(clientPubKey);

	printf("%s", hr); // print horizontal rule
	printf("Requesting broker public key from Key Manager\n");

	// send request to Key Manager to get public key of given broker
	if (sendto(sock, &request, sizeof(request), 0, (struct sockaddr *)
				&keyManagerServAddr, sizeof(keyManagerServAddr)) != sizeof(request))
			DieWithError("sendto() sent a different number of bytes than expected");


	// recieve a response from Key Manager
	key_to_principal_mesg response;
	memset(&response, 0, sizeof(response));

	if ((respStringLen = recvfrom(sock, &response, sizeof(response), 0,
				(struct sockaddr *) &fromAddr, &fromSize)) != sizeof(response))
			DieWithError("recvfrom() failed");

	if (keyManagerServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr){
		fprintf(stderr,"Error: recieved a packet from unknown source.\n");
		exit(1);
	}
	// END Send request/response to/from Key Manager (Get Broker Public Key)
	
	// set broker public key based on response from key manager
	brokerPubKey = ntohl(response.public_key);
	their_n = brokerPubKey / 1000;		 		// extract n from public key of broker
	their_e = fmod(brokerPubKey, 1000); 	// extract e from public key of broker

	printf("Handling client IP: %s   port:  %d\n", inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
	printf("Msg from Key Manager: Broker ID: %d   broker e: %d   broker n: %d\n\n", brokerID, their_e, their_n);

	// START Broker Communication
	// connect to broker 
	if (connect(TCPsock, (struct sockaddr *) &brokerServAddr, sizeof(brokerServAddr)) < 0)
		DieWithError("connect() failed");
	
	
	// prepare message for broker
	// allocate space from messages to/from broker
	client_broker_mesg my_msg;
	memset(&my_msg, 0, sizeof(my_msg));

	// encrypt first message to broker
	
	printf("%s", hr); // print horizontal rule
	printf("Encrypting using E=%d : N=%d and sending to broker\n", their_e, their_n);
	my_msg.request_type = htonl(Encrypt(action, their_e, their_n));
	my_msg.client_id = htonl(Encrypt(clientID, their_e, their_n));	
	my_msg.transaction_id = htonl(Encrypt(transaction_id, their_e, their_n));
	my_msg.num_stocks = htonl(Encrypt(num_stocks, their_e, their_n));
	// END prepare message for broker
	
	printf("brokerIP: %s   port: %d\n", inet_ntoa(brokerServAddr.sin_addr), ntohs(brokerServAddr.sin_port));
	// send request to Broker
	if (send(TCPsock, &my_msg, sizeof(my_msg), 0) != sizeof(my_msg))
		DieWithError("sendto() sent a different number of bytes than expected");


	// recieve msg from broker
	client_broker_mesg broker_msg;	
	memset(&broker_msg, 0, sizeof(broker_msg));   
	
	
	totalBytesRcvd = 0;
	do {
		if ((bytesRcvd = recv(TCPsock, &broker_msg, sizeof(broker_msg), 0)) != sizeof(broker_msg))
			DieWithError("recvfrom() failed");
			totalBytesRcvd += bytesRcvd;
	} while (totalBytesRcvd < sizeof(broker_msg));

	
	// print message from broker
	printf("%s", hr); // print horizontal rule
	printf("Handling client IP: %s   port:  %d\n", inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
	printf("\nMessage from broker - decrypting w/ d=%d and n=%d:\n", d, my_n);
	printf("Request Type: %s\n", client_broker_request_type[Decrypt(ntohl(broker_msg.request_type), d, my_n)]);   // client_broker_request_type from myCommonStructs.h
	printf("Client ID: %d\n", Decrypt(ntohl(broker_msg.client_id), d, my_n));
	printf("Transaction ID: %d\n", Decrypt(ntohl(broker_msg.transaction_id), d, my_n));
	printf("Num stocks: %d\n", Decrypt(ntohl(broker_msg.num_stocks), d, my_n));
	


	// send confirmation back to broker
	memset(&my_msg, 0, sizeof(my_msg));
	printf("%s", hr); // print horizontal rule
	printf("\nSend CONFIRM back to broker\n");
	printf("encrypting using E=%d : N=%d\n", their_e, their_n);
	my_msg.request_type = htonl(Encrypt(confirm, their_e, their_n));
	my_msg.client_id = htonl(Encrypt(Decrypt(ntohl(broker_msg.client_id), d, my_n), their_e, their_n));	
	my_msg.transaction_id = htonl(Encrypt(Decrypt(ntohl(broker_msg.transaction_id), d, my_n), their_e, their_n));
	my_msg.num_stocks = htonl(Encrypt(Decrypt(ntohl(broker_msg.num_stocks), d, my_n), their_e, their_n));

	// send request to Broker
	if (send(TCPsock, &my_msg, sizeof(my_msg), 0) != sizeof(my_msg))
		DieWithError("sendto() sent a different number of bytes than expected");


	// ^ wait for Done reponse from broker ^

	// recieve DONE msg from broker
	memset(&broker_msg, 0, sizeof(broker_msg));
	
	totalBytesRcvd = 0;
	do {
		if ((bytesRcvd = recv(TCPsock, &broker_msg, sizeof(broker_msg), 0)) != sizeof(broker_msg))
			DieWithError("recvfrom() failed");
			totalBytesRcvd += bytesRcvd;
	} while (totalBytesRcvd < sizeof(broker_msg));



	
	// print DONE message from broker
	printf("%s", hr); // print horizontal rule
	printf("Handling client IP: %s   port:  %d\n", inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
	printf("\nMessage from broker - decrypting w/ d=%d and n=%d:\n", d, my_n);
	printf("Request Type: %s\n", client_broker_request_type[Decrypt(ntohl(broker_msg.request_type), d, my_n)]);
	printf("Client ID: %d\n", Decrypt(ntohl(broker_msg.client_id), d, my_n));
	printf("Transaction ID: %d\n", Decrypt(ntohl(broker_msg.transaction_id), d, my_n));
	printf("Num stocks: %d\n", Decrypt(ntohl(broker_msg.num_stocks), d, my_n));


	close(sock);
	close(TCPsock);
	exit(0);
}

