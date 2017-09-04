#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>

typedef int bool;
#define true 1
#define false 0
#define maxReadBuffer 131072
#define maxGetBuffer 131071
#define smallReadBuffer 8192
#define smallGetBuffer 8191

//Sources Used: client.c and server.c provided by Benjamin Brewster, OSU CS344

//verifies client that has connected is valid
bool verifyClient(int clientFD){
	int charsWritten = 0, charsRead = 0;
	char clientNameBuffer[256];
	char serverResponseBuffer[16];
	memset(clientNameBuffer, '\0', sizeof(clientNameBuffer));
	memset(serverResponseBuffer, '\0', sizeof(serverResponseBuffer));
	
	//recieves name of client
	charsRead = recv(clientFD, clientNameBuffer, sizeof(clientNameBuffer) - 1, 0);
	if (charsRead < 0) fprintf(stderr, "ERROR reading from socket\n");
	
	//checks that name received is valid
	if(strcmp(clientNameBuffer, "otp_dec") == 0){
		strcpy(serverResponseBuffer, "Approved");
		//returns approved response to client
		charsWritten = send(clientFD, serverResponseBuffer, strlen(serverResponseBuffer), 0);
		if (charsWritten < 0) fprintf(stderr, "SERVER: ERROR writing to socket\n");
		if (charsWritten < strlen(serverResponseBuffer)) fprintf(stderr, "SERVER: WARNING: Not all data written to socket!\n");

		return true;
	}
	else
		strcpy(serverResponseBuffer, "Declined");
		//returns declined response to client
		charsWritten = send(clientFD, serverResponseBuffer, strlen(serverResponseBuffer), 0);
		if (charsWritten < 0) fprintf(stderr, "Server: ERROR writing to socket");
		if (charsWritten < strlen(serverResponseBuffer)) fprintf(stderr, "Server: WARNING: Not all data written to socket!\n");

		return false;
	
}


//sends a string to the client at file descriptor
void sendToClient(char *outData, int clientFD){
	int charsWritten = 0, checkSend = -5;
	char outMessage[maxReadBuffer];
	memset(outMessage, '\0', sizeof(outMessage));
	
	//add a terminal character to the end of the string
	strcpy(outMessage, outData);
	strcat(outMessage, "@");
	
	//send string with terminal character to the client
	charsWritten = send(clientFD, outMessage, strlen(outMessage), 0);
	if (charsWritten < 0) fprintf(stderr, "CLIENT-Send: ERROR writing to socket\n");
	if (charsWritten < strlen(outMessage)) fprintf(stderr, "CLIENT-Send: WARNING: Not all data written to socket!\n");
	
	do{
		ioctl(clientFD, TIOCOUTQ, &checkSend);
	}while(checkSend > 0);
	if(checkSend < 0){
		fprintf(stderr, "DEC SERVER IOCTL ERROR\n");
	}
}

//get a string from the file descriptor connection
void getFromClient(char *inData, int clientFD){
	int charsRead = 0;
	bool getCompleted = false;
	char* terminalChar;
	char readBuffer[smallReadBuffer];
	char completeData[maxReadBuffer];
	memset(completeData, '\0', sizeof(completeData));
	
	//loop until terminal character is detected
	while(getCompleted == false){
		memset(readBuffer, '\0', sizeof(readBuffer));
		
		charsRead = recv(clientFD, readBuffer, smallGetBuffer, 0);
		if (charsRead < 0) {
			fprintf(stderr, "CLIENT-Get: Error reading from socket\n");
		}
		//check readBuffer for terminal character
		if(strstr(readBuffer, "@") != NULL){
			getCompleted = true;
		}
		//copy readbuffer over if it is not empty
		if(strlen(readBuffer) > 0){
		strcat(completeData, readBuffer);
		}

		
	}
	//set pointer to terminal char, replace it with \0 and copy clean string back
	terminalChar = strstr(completeData, "@");
	strcpy(terminalChar, "\0");

	strcpy(inData, completeData);
}

//decrypts cipher text based on key, turning it into plaintext
void decrypt(char* plainText, char* key, char* cipherText){
	int i = 0, tempNum, keyNum;
	char tempPlain[maxReadBuffer];
	char tempKey[maxReadBuffer];
	char tempCipher[maxReadBuffer];
	memset(tempPlain, '\0', sizeof(tempPlain));
	memset(tempKey, '\0', sizeof(tempKey));
	memset(tempCipher, '\0', sizeof(tempCipher));
	strcpy(tempCipher, cipherText);
	strcpy(tempKey, key);
	//converts every element of cipher text to numerical equivalent
	//and applies key to it to modify
	for(i = 0; i < strlen(tempCipher); i++){
		if(tempCipher[i] == ' '){
			tempNum = 26;
		}
		else{
			tempNum = tempCipher[i] - 65;
		}
		
		if(tempKey[i] == ' '){
			tempNum -= 26;
		}
		else{
			tempNum -= tempKey[i] - 65;
		}
		
		if(tempNum < 0){
			tempNum += 27;
		}


		
		if(tempNum == 26){
			tempPlain[i] = ' ';
		}
		else{
			tempPlain[i] = tempNum + 65;
		}
		
	
	}
	tempPlain[strlen(tempCipher)] = '\0';
	strcpy(plainText, tempPlain);

}

void handleRequest(int clientFD){

	char plainTextBuffer[maxReadBuffer];
	char keyBuffer[maxReadBuffer];
	char cipherTextBuffer[maxReadBuffer];
	

	memset(plainTextBuffer, '\0', sizeof(plainTextBuffer));
	memset(keyBuffer, '\0', sizeof(keyBuffer));
	memset(cipherTextBuffer, '\0', sizeof(cipherTextBuffer));
	
	//verify the client is otp_enc
	verifyClient(clientFD);
	
	//get the plaintext
	getFromClient(cipherTextBuffer, clientFD);

	
	//get the key
	getFromClient(keyBuffer, clientFD);

	
	//decrypt the text
	decrypt(plainTextBuffer, keyBuffer, cipherTextBuffer);

	
	//send the cyphertext
	sendToClient(plainTextBuffer, clientFD);
	
}

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	int pid;
	socklen_t sizeOfClientInfo;
	char buffer[256];
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) {
		fprintf(stderr, "ERROR opening socket\n");
		exit(2);
	}

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
		fprintf(stderr, "ERROR on binding\n");
		exit(2);
	}
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	// Accept a connection, blocking if one is not available until one connects
	sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
	
	while(1){
		
	establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
	if (establishedConnectionFD < 0) {
		fprintf(stderr, "ERROR on accept\n");
		exit(2);
	}
	
	//fork child process to handle new request
	pid=fork();
	
	if(pid < 0){
		fprintf(stderr, "otp_enc fork failed\n");
	}
	else if(pid == 0){
	
	handleRequest(establishedConnectionFD);

	//close both connections as this is the child
	close(establishedConnectionFD);
	close(listenSocketFD);
	
	//request succesfully received and processed, exit 0
	exit(0);
	}
	
	//close the most recent connection
	close(establishedConnectionFD);
	}
	

	
	return 0; 
}
