#ifndef CIPHER_H
#define CIPHER_H

#include <stdbool.h>

/// @brief Check if the string consists of only letters.
/// @param str The given string.
/// @return true if the string contains only letters or false
/// if otherwise.
bool check_key(const char *const str);

/// @brief Perform encryption or decryption of the string based 
/// on the indicator.
/// @param secret_key The secret key.
/// @param ch The character to encrypt or decrypt.
/// @param indicator Perform encryption if true or decryption if false.
/// @return The result of the decryption or encryption.
char get_substitution(char secret_key, char ch, bool indicator);

/// @brief Encrypt the plain text based on the secret key and store the result.
/// @param plain_text The plain text to encrypt.
/// @param cipher_text Holds the encrypted text.
/// @param secret_key The secret key for encrypting the text.
void encrypt(const char *const plain_text, char cipher_text[], const char *const secret_key);

/// @brief Decrypts the encrypted text based on the secret. 
/// key and store the result.
/// @param cipher_text The encrypted text to decrypt.
/// @param plain_text Holds the decrypted text.
/// @param secret_key The secret key for decrypting the text
void decrypt(const char *const cipher_text, char plain_text[], const char *const secret_key);

#endif