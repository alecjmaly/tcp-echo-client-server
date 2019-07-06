#!/bin/bash
$(gcc TCPEchoClient.c DieWithError.c -o client -std=c99 -lm)
$(gcc TCPEchoServer.c HandleTCPClient.c DieWithError.c -o server -std=gnu99 -lm -lpthread)
$(gcc KeyManager.c DieWithError.c -o keymanager) 

