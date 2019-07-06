# TCP Echo Client + Servers in C


This project was designed to support multi-threading of clients to gain extra credit as an undergrad.

Assumptions:
  - Agreed upon method of storing keys between all machines : int value = n*1000+e. This will be used to save/retrieve both n and e from the public key.
  - Clients and Brokers choose unique Principal IDs
  - Prime numbers should be chosen for <p> and <q> - these will be used to generate a small e and corresponding d for message encryption and decryption using public/private key schema (RSA)
  - Instructions never declared there should be a loop in client. It quits automatically after recieving done message from broker. Exit can be accomplished from broker using Ctrl+C.
  - Assumes .csv is already created with headers for Key Manager use

Notes:
  - This is not the most efficient or robust code. Much error handling and optimizations can be implemented. That said, I believe it suits the project requirements. 
  - These were created and compiled on the emunix.emich.edu server.



## Programs can be compiled using the provided bash script (build.sh) by running:  bash build.sh
  $(gcc TCPEchoClient.c DieWithError.c -o client -std=c99 -lm)
  $(gcc TCPEchoServer.c HandleTCPClient.c DieWithError.c -o server -std=gnu99 -lm -lpthread)
  $(gcc KeyManager.c DieWithError.c -o keymanager) 




## Details

### Key Manager:
  parameters: ./keymanager <UDP SERVER PORT>
  run example :  ./keymanager 1500


### Broker:
  parameters ./server <THIS BROKER's UDP PORT> <THIS BROKER's TCP PORT> <Broker ID> <p> <q> <Key Manager IP> <Key Manager Port>
  run example: ./server 1501 1501 5 59 107 127.0.0.1 1500


### Client:
  parameters: ./client <Server/Broker IP> <Broker TCP Port> <Broker ID> <Client ID> <p> <q> [<KeyManager Port>]
  run example: ./client 127.0.0.1 1501 5 18 113 31 1500








