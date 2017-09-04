#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <time.h>
#include <sys/ioctl.h>

typedef int bool;
#define true 1
#define false 0
#define maxReadBuffer 131072
#define smallReadBuffer 1024
#define smallGetBuffer 1023
#define maxGetBuffer 131071

//Sources Used: client.c and server.c provided by Benjamin Brewster, OSU CS344

//verify connected to a valid server
bool verifyServer(int serverFD, char* programName){
	int charsWritten = 0, charsRead = 0;
	char responseBuffer[16];
	memset(responseBuffer, '\0', sizeof(responseBuffer));
	
	//send the server the name of the client for verification
	charsWritten = send(serverFD, programName, strlen(programName), 0);
	if (charsWritten < 0){
		fprintf(stderr, "CLIENT-ver: ERROR writing to socket\n");
	}
	if (charsWritten < strlen(programName)) fprintf(stderr, "CLIENT-Ver: WARNING: Not all data written to socket!\n");
	
	//recv confirmation from the server
	charsRead = recv(serverFD, responseBuffer, sizeof(responseBuffer), 0);
	if (charsRead < 0){
		fprintf(stderr, "CLIENT-Ver: ERROR reading from socket");
	}

	//check if server approved or declined connection
	if(strcmp(responseBuffer, "Approved") != 0){
		fprintf(stderr, "Error: Server Declined Connection - Invalid Client: Must Connect to OTP_ENC_D\n");
		exit(1);
	}
	else
		return true;
}

//send a string to the file descriptor connection
void sendToServer(char *outData, int serverFD){
	int charsWritten = 0, checkSend = -5;
	char outMessage[maxReadBuffer];
	memset(outMessage, '\0', sizeof(outMessage));
	
	//add a terminal character to the end of the string
	strcpy(outMessage, outData);
	strcat(outMessage, "@");

	//send string with terminal character to the server
	charsWritten = send(serverFD, outMessage, strlen(outMessage), 0);
	if (charsWritten < 0){
		fprintf(stderr, "CLIENT-Send: Error writing to socket\n");
	}
	if (charsWritten < strlen(outMessage)) printf("CLIENT-Send: WARNING: Not all data written to socket!\n");
	
	//ensures sending of all data
	do{
		ioctl(serverFD, TIOCOUTQ, &checkSend);
	}while(checkSend > 0);
	if(checkSend < 0){
		fprintf(stderr, "ENC CLIENT IOCTL ERROR\n");
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
		//check for presence of terminal character
		if(strstr(readBuffer, "@") != NULL){
			getCompleted = true;
		}

		if(strlen(readBuffer) > 0){

		strcat(completeData, readBuffer);
		}

		
	}
	//set pointer to terminal char, replace it with \0 and copy clean string back
	terminalChar = strstr(completeData, "@");
	strcpy(terminalChar, "\0");

	strcpy(inData, completeData);

}



//check a string for invalid characters
bool verifyChars(char *stringToCheck){
	int i = 0;
	//check every value of a string for invalid characters
	for(i = 0; i < strlen(stringToCheck); i++){
		
		if((stringToCheck[i] < 65 || stringToCheck[i] > 90) && stringToCheck[i] != 32){
			return false;
		}
	}
	return true;
}

void makeRequest(int serverFD, char* programName, char* plainTextFileName, char* keyFileName){

	FILE * plainTextFile, * keyFile;
	char plainTextBuffer[maxReadBuffer];
	char fileReadBuffer[maxReadBuffer];
	char keyBuffer[maxReadBuffer];
	char cipherBuffer[maxReadBuffer];
	char cleanBuffer[maxReadBuffer];
	char* token = NULL;
	char* bufferClean;
	int i;
	memset(plainTextBuffer, '\0', sizeof(plainTextBuffer));
	memset(keyBuffer, '\0', sizeof(keyBuffer));
	memset(cipherBuffer, '\0', sizeof(cipherBuffer));
	memset(fileReadBuffer, '\0', sizeof(fileReadBuffer));
	memset(cleanBuffer, '\0', sizeof(cleanBuffer));

	//open and read plaintext file
	plainTextFile = fopen(plainTextFileName, "r");
	fgets(fileReadBuffer, maxReadBuffer, plainTextFile);
	token = strtok(fileReadBuffer, "\n");
	strcpy(plainTextBuffer, token);
	
	//open and read keyfile
	memset(fileReadBuffer, '\0', sizeof(fileReadBuffer));
	keyFile = fopen(keyFileName, "r");
	fgets(fileReadBuffer, maxReadBuffer, keyFile);
	token = strtok(fileReadBuffer, "\n");
	strcpy(keyBuffer, token);
	
	//check if key is shorter than the plaintext
	if(strlen(plainTextBuffer) > strlen(keyBuffer)){
		fprintf(stderr, "Error: key '%s' is too short\n", keyFileName);
		exit(1);
	}
	if(verifyChars(keyBuffer) == false || verifyChars(plainTextBuffer) == false){
		fprintf(stderr, "otp_enc error: input contains bad characters\n");
		exit(1);
	}
	
	//connects to server for verification client is ok
	verifyServer(serverFD, programName);
	
	//send the plaintext
	sendToServer(plainTextBuffer, serverFD);
	
	//send the key 
	sendToServer(keyBuffer, serverFD);
	
	getFromServer(cipherBuffer, serverFD);
	
	//copy cipherBuffer (using size of plaintext) to a clean buffer to ensure no junk characters
	strncpy(cleanBuffer, cipherBuffer, strlen(plainTextBuffer));
	
	//print the cypher text
	printf("%s\n", cleanBuffer);
	fclose(plainTextFile);
	fclose(keyFile);
}

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[256];
	char keyFileNameBuffer[256];
	char plainTextFileNameBuffer[256];
    
	if (argc < 4) { fprintf(stderr,"USAGE: %s plaintext keyfile port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	memset(keyFileNameBuffer, '\0', sizeof(keyFileNameBuffer));
	memset(plainTextFileNameBuffer, '\0', sizeof(plainTextFileNameBuffer));

	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(2); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	
	strcpy(plainTextFileNameBuffer, argv[1]);
	strcpy(keyFileNameBuffer, argv[2]);

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0){
		fprintf(stderr, "CLIENT: ERROR opening socket\n");
		exit(2);
	}
	
	
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){ // Connect socket to address
		fprintf(stderr, "CLIENT: ERROR connecting\n");
		exit(2);
	}
	
	//request encryption
	makeRequest(socketFD, argv[0], plainTextFileNameBuffer, keyFileNameBuffer);

	close(socketFD); // Close the socket
	return 0;
}
