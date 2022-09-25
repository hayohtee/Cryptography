#include <stdio.h>
#include <string.h>
#include "cipher.h"

#define SIZE 100

int main()
{
    char text[SIZE];
    char secret_key[SIZE];
    char encryptedText[SIZE];
    
    puts("Enter plain text to encrypt");
    printf("%s", "$: ");
    
    fgets(text, SIZE, stdin);
    text[strlen(text) - 1] = '\0';

    puts("Enter secret key containing only letters");
    printf("%s", "$: ");
    scanf("%s", secret_key);

    encrypt(text, encryptedText, secret_key);

    printf("\nEncrypted text:\n%s\n", encryptedText);

    char decryptedText[SIZE];
    decrypt(encryptedText, decryptedText, secret_key);

    printf("\nDecrypting \"%s\" gives: %s\n", encryptedText, decryptedText);

    return 0;
}