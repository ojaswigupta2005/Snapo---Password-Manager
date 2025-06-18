#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sha256.h"

// Encrypting/decrypting using XOR
void XOR(char *pass, int key)
{
    for (int i = 0; pass[i] != '\0'; i++)
    {
        pass[i] ^= key;
    }
}

int password_strength(char *password)
{
    int length = strlen(password);
    int upper_case = 0, lower_case = 0, numb = 0;
    if (length < 8)
    {
        printf("Password must be at least 8 characters long including at least one upper case letter, one lower case letter and a number.\n");
        return 0;
    }

    for (int i = 0; i < length; i++)
    {
        if (password[i] >= 'A' && password[i] <= 'Z')
            upper_case = 1;
        if (password[i] >= 'a' && password[i] <= 'z')
            lower_case = 1;
        if (password[i] >= '0' && password[i] <= '9')
            numb = 1;
    }

    if (!upper_case)
        printf("Password must contain at least one uppercase letter.\n");
    if (!lower_case)
        printf("Password must contain at least one lowercase letter.\n");
    if (!numb)
        printf("Password must contain at least one digit.\n");

    return (upper_case && lower_case && numb);
}

void setup_master_password()
{
    FILE *file = fopen("master.hash", "r");
    if (file)
    {
        fclose(file);
        return; // Already set
    }

    char master[100], hash[65];
    int k = 0;

    while (!k)
    {
        printf("Set a master password: ");
        if (fgets(master, sizeof(master), stdin) == NULL)
        {
            printf("Input error.\n");
            continue;
        }
        master[strcspn(master, "\n")] = '\0'; // Remove newline
        if (strlen(master) == 0)
        {
            printf("Password cannot be empty!\n");
            continue;
        }

        k = password_strength(master);
    }

    sha256_string(master, hash);

    file = fopen("master.hash", "w");
    if (!file)
    {
        printf("Error creating hash file\n");
        exit(1);
    }

    fprintf(file, "%s", hash);
    fclose(file);
    printf("Master password set and saved securely.\n");
}

int verify_master_password()
{
    FILE *file = fopen("master.hash", "r");
    if (!file)
    {
        printf("Master password not set. Please restart the program.\n");
        return 0;
    }

    char stored_hash[65];
    char entered[100];
    char entered_hash[65];

    fscanf(file, "%64s", stored_hash);
    fclose(file);

    printf("Enter master password: ");
    scanf("%99s", entered);

    sha256_string(entered, entered_hash);

    if (strcmp(stored_hash, entered_hash) == 0)
    {
        printf("Login successful.\n");
        return 1;
    }
    else
    {
        printf("Incorrect master password!\n");
        return 0;
    }
}

void hex_to_bytes(const char *hex, unsigned char *bytes, int len)
{
    for (int i = 0; i < len; i++)
    {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

void encrypt_password_flow()
{
    char pass[1000];
    char web[100];
    char task[10];

    printf("Enter Website: ");
    scanf("%99s", web);
    while (getchar() != '\n')
        ; // Clear input buffer

    printf("Add or Find?\n");
    scanf("%9s", task);

    if (strcmp(task, "Add") == 0)
    {
        printf("Enter password for %s: ", web);
        while (getchar() != '\n')
            ; // Clear input buffer
        fgets(pass, sizeof(pass), stdin);
        pass[strcspn(pass, "\n")] = '\0';

        XOR(pass, 7);

        FILE *file = fopen("encrypted_password.txt", "a");
        if (!file)
        {
            perror("Failed to open file");
            exit(EXIT_FAILURE);
        }

        fprintf(file, "%s ", web); // Store the website
        for (int i = 0; pass[i] != '\0'; i++)
        {
            fprintf(file, "%02X", (unsigned char)pass[i]); // Hex format
        }
        fprintf(file, "\n");
        fclose(file);

        printf("Encrypted password saved.\n");
    }
    else if (strcmp(task, "Find") == 0)
    {
        char search_web[100], hex_pass[200];

        FILE *file = fopen("encrypted_password.txt", "r");
        if (!file)
        {
            perror("Failed to open file");
            exit(EXIT_FAILURE);
        }

        int found = 0;
        while (fscanf(file, "%s %s", search_web, hex_pass) == 2)
        {
            if (strcmp(search_web, web) == 0)
            {
                found = 1;
                break;
            }
        }
        fclose(file);

        if (found)
        {
            int hex_len = strlen(hex_pass);
            int byte_len = hex_len / 2;
            unsigned char password_bytes[byte_len + 1]; // +1 for null-terminator
            password_bytes[byte_len] = '\0';

            hex_to_bytes(hex_pass, password_bytes, byte_len);
            XOR((char *)password_bytes, 7);

            printf("Decrypted password: %s\n", password_bytes);
        }
        else
        {
            printf("Website not found.\n");
        }
    }
    else
    {
        printf("Invalid task. Please enter 'Add' or 'Find'.\n");
    }
}

int main()
{
    setup_master_password();

    if (!verify_master_password())
    {
        return 1;
    }

    printf("Access granted to password manager.\n");
    encrypt_password_flow();

    return 0;
}
