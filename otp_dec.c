#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/ioctl.h>

typedef int bool;
#define true 1
#define false 0
#define maxReadBuffer 131072
#define maxGetBuffer 131071
#define smallReadBuffer 8192
#define smallGetBuffer 8191

//Sources Used: client.c and server.c provided by Benjamin Brewster, OSU CS344

//contacts server to verify connection
bool verifyServer(int serverFD, char* programName){
	int charsWritten = 0, charsRead = 0;
	char responseBuffer[16];
	memset(responseBuffer, '\0', sizeof(responseBuffer));
	
	
	//send the server the name of the client for verification
	charsWritten = send(serverFD, programName, strlen(programName), 0);
	if (charsWritten < 0) fprintf(stderr, "CLIENT-Ver: ERROR writing to socket\n");
	if (charsWritten < strlen(programName)) fprintf(stderr, "CLIENT-Ver: WARNING: Not all data written to socket!\n");
	
	//recv confirmation from the server
	charsRead = recv(serverFD, responseBuffer, sizeof(responseBuffer), 0);
	if (charsRead < 0) fprintf(stderr, "CLIENT-Ver: ERROR reading from socket\n");
	
	//check if server approved or declined connection
	if(strcmp(responseBuffer, "Approved") != 0){
		fprintf(stderr, "Error: Server Declined Connection - Invalid Client: Must Connect to OTP_DEC_D\n");
		exit(1);
	}
	else
		return true;
}

//sends a string to the server in the file descriptor
void sendToServer(char *outData, int serverFD){
	int charsWritten = 0, checkSend = -5;
	char outMessage[maxReadBuffer];
	memset(outMessage, '\0', sizeof(outMessage));
	
	//add a terminal character to the end of the string
	strcpy(outMessage, outData);
	strcat(outMessage, "@");
	
	//send string with terminal character to the server
	charsWritten = send(serverFD, outMessage, strlen(outMessage), 0);
	if (charsWritten < 0) fprintf(stderr, "CLIENT-Send: ERROR writing to socket\n");
	if (charsWritten < strlen(outMessage)) fprintf(stderr, "CLIENT-Send: WARNING: Not all data written to socket!\n");
	
	do{
	ioctl(serverFD, TIOCOUTQ, &checkSend);
	}while(checkSend > 0);
	if(checkSend < 0){
		fprintf(stderr, "DEC CLIENT IOCTL ERROR\n");
	}
}

//get a string from the file descriptor connection
void getFromServer(char *inData, int serverFD){
	int charsRead = 0;
	bool getCompleted = false;
	char* terminalChar;
	char readBuffer[smallReadBuffer];
	char completeData[maxReadBuffer];
	memset(completeData, '\0', sizeof(completeData));
	
	//loop until terminal character is detected
	while(getCompleted == false){
		memset(readBuffer, '\0', sizeof(readBuffer));
		
		charsRead = recv(serverFD, readBuffer, smallGetBuffer, 0);
		if (charsRead < 0) {
			fprintf(stderr, "CLIENT-Get: Error reading from socket\n");
		}
		//check for terminal character
		if(strstr(readBuffer, "@") != NULL){
			getCompleted = true;
		}
		//if the readBuffer isn't empty, copy it over
		if(strlen(readBuffer) > 0){
		strcat(completeData, readBuffer);
		}

		
	}
	//set pointer to terminal char, replace it with \0 and copy clean string back
	terminalChar = strstr(completeData, "@");
	strcpy(terminalChar, "\0");

	strcpy(inData, completeData);
}

//verifies the string (no invalid characters)
bool verifyChars(char *stringToCheck){
	int i = 0;
	//checks every value in the string for invalid characters
	for(i = 0; i < strlen(stringToCheck); i++){
		
		if((stringToCheck[i] < 65 || stringToCheck[i] > 90) && stringToCheck[i] != 32){
			return false;
		}
	}
	return true;
}

//connects to a server to have a file decrypted
void makeRequest(int serverFD, char* programName, char* cipherTextFileName, char* keyFileName){
	//int plainTextFileStatus, keyFileStatus;
	FILE * cipherTextFile, * keyFile;
	char cipherTextBuffer[maxReadBuffer];
	char fileReadBuffer[maxReadBuffer];
	char keyBuffer[maxReadBuffer];
	char plainTextBuffer[maxReadBuffer];
	char cleanBuffer[maxReadBuffer];
	char* token = NULL;
	memset(plainTextBuffer, '\0', sizeof(plainTextBuffer));
	memset(keyBuffer, '\0', sizeof(keyBuffer));
	memset(cipherTextBuffer, '\0', sizeof(cipherTextBuffer));
	memset(fileReadBuffer, '\0', sizeof(fileReadBuffer));
	memset(cleanBuffer, '\0', sizeof(cleanBuffer));

	//open, read, and process cipher text file
	cipherTextFile = fopen(cipherTextFileName, "r");
	fgets(fileReadBuffer, maxReadBuffer, cipherTextFile);
	token = strtok(fileReadBuffer, "\n");
	strcpy(cipherTextBuffer, token);

	
	//open, read, and process keyfile
	memset(fileReadBuffer, '\0', sizeof(fileReadBuffer));
	keyFile = fopen(keyFileName, "r");
	fgets(fileReadBuffer, maxReadBuffer, keyFile);
	token = strtok(fileReadBuffer, "\n");
	strcpy(keyBuffer, token);

	
	//verifies the key buffer is larger than the cipher text
	if(strlen(cipherTextBuffer) > strlen(keyBuffer)){
		fprintf(stderr, "Error: key '%s' is too short\n", keyFileName);
		exit(1);
	}
	//verifies that key and cipher text have no invalid characters
	if(verifyChars(keyBuffer) == false || verifyChars(cipherTextBuffer) == false){
		fprintf(stderr, "otp_enc error: input contains bad characters\n");
		exit(1);
	}
	
	//connects to server for verification client is ok
	verifyServer(serverFD, programName);
	
	//send the plaintext filename
	sendToServer(cipherTextBuffer, serverFD);
	
	//send the key filename
	sendToServer(keyBuffer, serverFD);
	
	getFromServer(plainTextBuffer, serverFD);
	
	strncpy(cleanBuffer, plainTextBuffer, strlen(cipherTextBuffer));
	
	//print the plaint text
	printf("%s\n", plainTextBuffer);
	fclose(cipherTextFile);
	fclose(keyFile);
}

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[256];
	char keyFileNameBuffer[256];
	char cipherTextFileNameBuffer[256];
    
	if (argc < 4) { fprintf(stderr,"USAGE: %s ciphertext keyfile port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	memset(keyFileNameBuffer, '\0', sizeof(keyFileNameBuffer));
	memset(cipherTextFileNameBuffer, '\0', sizeof(cipherTextFileNameBuffer));

	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(1); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	
	strcpy(cipherTextFileNameBuffer, argv[1]);
	strcpy(keyFileNameBuffer, argv[2]);

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) {
		fprintf(stderr, "CLIENT: ERROR opening socket\n");
		exit(2);
	}
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
		fprintf(stderr, "CLIENT: Error connecting\n");
		exit(2);
	}
		
	//requets decryption of the cipher	
	makeRequest(socketFD, argv[0], cipherTextFileNameBuffer, keyFileNameBuffer);

	close(socketFD); // Close the socket
	return 0;
}
