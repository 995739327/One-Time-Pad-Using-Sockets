#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    int charCount, i, randomNum;
    char argBuffer[32];
    char* key;
    time_t t;

    //seeds random number generator
    srand((unsigned) time(&t));

    //printf("%d\n", argc);

    memset(argBuffer, '\0', sizeof(argBuffer));
    strcpy(argBuffer, argv[1]);
    charCount = atoi(argBuffer);
    //printf("Input: %s, Integer: %d\n", argBuffer, charCount);

    //creates a dynamically allocated string with space for key
    //plus a newline character and \0
    key = (char*)malloc((charCount + 2) * sizeof(char));



    for(i = 0; i < charCount; i++){
        randomNum = rand();
        //1 in 27 chance the char is a space
        if(randomNum % 27 == 0){
            key[i] = ' ';
            //printf(" ");
        }
        //else it will be a capital letter from A(65) to Z(90)
        else{
            key[i] = randomNum % 26 + 65;
            //printf("%c", key[i]);
        }
    }

    key[charCount] = '\n';
    key[charCount + 1] = '\0';

    //printf("\nKey:\n%s\n", key);
    printf("%s", key);
	
	free(key);

    return 0;
}