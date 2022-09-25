#include "cipher.h"
#include <ctype.h>
#include <string.h>

bool check_key(const char *const str)
{
    int len = strlen(str);

    for (int i = 0; i < len; i++)
    {
        if (!isalpha(str[i]))
            return false;
    }

    return true;
}

char get_substitution(char secret_key, char ch, bool indicator)
{
    static const char vigenere_square[26][26] =
        {
            {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
             'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'},
            {'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
             'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A'},
            {'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
             'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B'},
            {'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
             'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C'},
            {'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
             'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D'},
            {'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
             'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E'},
            {'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F'},
            {'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
             'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G'},
            {'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
             'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'},
            {'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
             'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'},
            {'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
             'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'},
            {'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
             'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K'},
            {'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A',
             'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L'},
            {'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B',
             'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M'},
            {'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C',
             'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N'},
            {'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D',
             'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O'},
            {'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E',
             'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'},
            {'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F',
             'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q'},
            {'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
             'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R'},
            {'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
             'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S'},
            {'U', 'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
             'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T'},
            {'V', 'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
             'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U'},
            {'W', 'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
             'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V'},
            {'X', 'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
             'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'},
            {'Y', 'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
             'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X'},
            {'Z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
             'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y'}};

    char result = ch;

    if (indicator == true) // Perform encryption
    {
        result = vigenere_square[toupper(secret_key) - 'A'][toupper(ch) - 'A'];
    }
    else // Perform decryption
    {
        int row = toupper(secret_key) - 'A';
        int column = 0;

        for (column = 0; column < 26; column++)
        {
            if (vigenere_square[row][column] == toupper(ch))
                break;
        }

        result = 'A' + column;
    }

    // Return the result preserving the case.
    return (isupper(ch) ? result : tolower(result));
}

void encrypt(const char *const plain_text, char cipher_text[], const char *const secret_key)
{
    if (!check_key(secret_key))
        return;

    int len = strlen(plain_text);
    int len_secret_key = strlen(secret_key);
    int key_counter = 0;

    for (int i = 0; i < len; i++)
    {
        cipher_text[i] = plain_text[i];

        if (isalpha(plain_text[i]))
        {
            cipher_text[i] = get_substitution(secret_key[key_counter % len_secret_key],
                                              plain_text[i], true);
            key_counter++;
        }
    }

    cipher_text[len] = '\0';
}

void decrypt(const char *const cipher_text, char plain_text[], const char *const secret_key)
{
    if (!check_key(secret_key))
        return;

    int len = strlen(cipher_text);
    int len_secret_key = strlen(secret_key);
    int key_counter = 0;

    for (int i = 0; i < len; i++)
    {
        plain_text[i] = cipher_text[i];

        if (isalpha(cipher_text[i]))
        {
            plain_text[i] = get_substitution(secret_key[key_counter % len_secret_key],
                                             cipher_text[i], false);
            key_counter++;
        }
    }

    plain_text[len] = '\0';
}
