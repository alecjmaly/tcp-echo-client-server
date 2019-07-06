#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for recv() and send() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <unistd.h>     /* for close() */
#include <string.h>     /* for memset() */
#include <math.h>
#include "myCommonStructs.h"		// shared structs for communicating between hosts
//#include "RSAfunctions.h"			// everything needed for RSA 


#define RCVBUFSIZE 32   /* Size of receive buffer */

void DieWithError(char *errorMessage);  /* Error handling function */
int Encrypt(int msg, int e, int n);
int Decrypt(int e_msg, int d, int n);


void HandleTCPClient(int clntSock, int my_e, int d, int my_n, int km_sock, const struct sockaddr_in *km_addr)
{
    struct sockaddr_in keyManagerServAddr;
    principal_to_key_mesg km_request;
    key_to_principal_mesg km_response;
    client_broker_mesg request;
    client_broker_mesg response;
    struct sockaddr_in fromAddr;
    int recvMsgSize, cliAddrLen;
	int clientPubKey; // more vars for public and private keys
	int their_e, their_n; 	// variables for public key

    const char *hr = "\n----------------------------------------------\n";  // horizontal rule

	memset(&keyManagerServAddr, 0, sizeof(keyManagerServAddr));
	keyManagerServAddr.sin_family = AF_INET;
	keyManagerServAddr.sin_addr.s_addr = inet_addr(inet_ntoa(km_addr->sin_addr));
	keyManagerServAddr.sin_port = htons(ntohs(km_addr->sin_port));


    // loop until received confirm message
    do { 
        memset(&request, 0, sizeof(request));
        memset (&response, 0, sizeof(response));
        int totalBytesRcvd = 0, bytesRcvd;
        
        // loop while still have more data
       
		// recieve message
        totalBytesRcvd = 0;
		do { 
            if ((bytesRcvd = recv(clntSock, &request, sizeof(request), 0)) < 0)
                DieWithError("recv() failed or connection closed prematurely");
            totalBytesRcvd += bytesRcvd;
        } while (totalBytesRcvd < sizeof(request)); 


        printf("decrypting using e=%d  n=%d   d=%d\n", my_e, my_n, d);
        printf("request: %s\n", client_broker_request_type[Decrypt(ntohl(request.request_type), d, my_n)]);   // client_broker_request_type from myCommonStructs.h
        printf("client id: %d\n", Decrypt(ntohl(request.client_id), d, my_n));
        printf("transaction id: %d\n", Decrypt(ntohl(request.transaction_id), d, my_n));
        printf("num stocks: %d\n", Decrypt(ntohl(request.num_stocks), d, my_n));        
        



        switch (Decrypt(ntohl(request.request_type), d, my_n)){
            case 0:	 // buy 
            case 1:  // sell
                memset(&km_request, 0, sizeof(km_request));
                
                km_request.request_type = htonl(request_key);
                km_request.principal_id = htonl(Decrypt(ntohl(request.client_id), d, my_n));
                //km_request.public_key = htonl(brokerPubKey);
                
                printf("%s", hr); // print horizontal rule
                printf("Requesting public key of client from Key Manager.\n");

                // send request to key manager  :  get public key
                if (sendto(km_sock, &km_request, sizeof(km_request), 0, (struct sockaddr *)
                            &keyManagerServAddr, sizeof(keyManagerServAddr)) != sizeof(km_request))
                    DieWithError("sendto() [breaks here] sent a different number of bytes than expected");

                // recieve a response from Key Manager
                memset(&km_response, 0, sizeof(km_response));
                
                /* Block until receive message from key manager */
                if ((recvMsgSize = recvfrom(km_sock, &km_response, sizeof(km_response), 0,
                            (struct sockaddr *) &fromAddr, &cliAddrLen)) < 0)
                    DieWithError("recvfrom() failed");

                // set client public keys from key manager request
                clientPubKey = ntohl(km_response.public_key);
                their_n = clientPubKey / 1000;
                their_e = fmod(clientPubKey, 1000);

                printf("Handling client IP: %s   port:  %d\n", inet_ntoa(fromAddr.sin_addr), ntohs(fromAddr.sin_port));
                printf("Message from Key Manager - client e: %d  client n: %d  > from %d\n", their_e, their_n, ntohl(km_response.public_key));

                // send CONFIRM back to client - encrypt with client public key
                memset (&response, 0, sizeof(response));
                response.request_type = htonl(Encrypt(confirm, their_e, their_n)); // confirm transaction
                response.client_id = htonl(Encrypt(Decrypt(ntohl(request.client_id), d, my_n), their_e, their_n));
                response.transaction_id = htonl(Encrypt(Decrypt(ntohl(request.transaction_id), d, my_n), their_e, their_n)); 
                response.num_stocks = htonl(Encrypt(Decrypt(ntohl(request.num_stocks), d, my_n), their_e, their_n));

                printf("\nSending CONFIRM back to client - encrypting w/ e=%d and n=%d\n\n", their_e, their_n);
                if (send(clntSock, &response, sizeof(response), 0) != sizeof(response))
                    DieWithError("sendto() sent a different number of bytes than expected");

                break;	
            case 2: // recieve confirm from client 
                // send back DONE message to client - encrypt with client public key
                memset(&response, 0, sizeof(response));		

                response.request_type = htonl(Encrypt(done, their_e, their_n)); // confirm transaction
                response.client_id = htonl(Encrypt(Decrypt(ntohl(request.client_id), d, my_n), their_e, their_n));
                response.transaction_id = htonl(Encrypt(Decrypt(ntohl(request.transaction_id), d, my_n), their_e, their_n)); 
                response.num_stocks = htonl(Encrypt(Decrypt(ntohl(request.num_stocks), d, my_n), their_e, their_n));

                printf("%s", hr); // print horizontal rule
                printf("\nSending DONE to client - encrypting w/ e=%d and n=%d\n",  their_e, their_n);

                if (send(clntSock, &response, sizeof(response), 0) != sizeof(response))
                    DieWithError("sendto() sent a different number of bytes than expected");
                
                printf("%s", hr); // print horizontal rule
                printf("FINISHED COMMUNICATING WITH CLIENT");
                printf("%s", hr); // print horizontal rule
                break;
            default:
                printf("Invalid action recieved from Client.");					
        }		

    } while (Decrypt(ntohl(request.request_type), d, my_n) != 2);



    close(clntSock);    /* Close client socket */
}
