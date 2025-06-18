#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sha256.h"

void XOR(char *pass, int key);
int password_strength(char *password);
void setup_master_password(GtkWidget *widget, gpointer data);
int verify_master_password(GtkWidget *widget, gpointer data);
void encrypt_password_flow(GtkWidget *widget, gpointer data);
void decrypt_password_flow(GtkWidget *widget, gpointer data);
void hex_to_bytes(const char *hex, unsigned char *bytes, int len);

// XOR
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

    return (upper_case && lower_case && numb);
}

// Set master password if not set
void setup_master_password(GtkWidget *widget, gpointer data)
{
    GtkWidget *password_dialog = gtk_dialog_new_with_buttons("Set Master Password",
                                                             GTK_WINDOW(gtk_widget_get_toplevel(widget)),
                                                             GTK_DIALOG_MODAL,
                                                             "_Cancel", GTK_RESPONSE_CANCEL,
                                                             "_Set Password", GTK_RESPONSE_OK,
                                                             NULL); // dialog modal ensures not moving forward before master pass

    GtkWidget *password_entry = gtk_entry_new();                                        // entry box
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);                         // hides password
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Enter Master Password"); // peeche wala content when nothing typed

    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(password_dialog))),
                       password_entry, TRUE, TRUE, 0); // parameters(expand,fill,padding)

    gtk_widget_show_all(password_dialog);

    int response = gtk_dialog_run(GTK_DIALOG(password_dialog));

    // setup master pass
    if (response == GTK_RESPONSE_OK) // checks password strength and gives outputs accordingly
    {
        const char *master_password = gtk_entry_get_text(GTK_ENTRY(password_entry));
        if (password_strength((char *)master_password))
        {
            char hash[65];
            sha256_string(master_password, hash);

            // Save hash to file
            FILE *file = fopen("master.hash", "w");
            if (!file)
            {
                perror("Error creating hash file");
                exit(1);
            }
            fprintf(file, "%s", hash);
            fclose(file);

            printf("Master password set and saved securely.\n");
        }
        else
        {
            printf("Password does not meet strength requirements.\n");
        }
    }

    gtk_widget_destroy(password_dialog); // closinf that dialog box
}

// Verifying master pass
int verify_master_password(GtkWidget *widget, gpointer data)
{
    GtkWidget *password_dialog = gtk_dialog_new_with_buttons("Enter Master Password",
                                                             GTK_WINDOW(gtk_widget_get_toplevel(widget)),
                                                             GTK_DIALOG_MODAL,
                                                             "_Cancel", GTK_RESPONSE_CANCEL,
                                                             "_Verify Password", GTK_RESPONSE_OK,
                                                             NULL);

    GtkWidget *password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Enter Master Password");

    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(password_dialog))),
                       password_entry, TRUE, TRUE, 0);

    gtk_widget_show_all(password_dialog); // user entered password

    int response = gtk_dialog_run(GTK_DIALOG(password_dialog));

    // checking user entered password
    if (response == GTK_RESPONSE_OK)
    {
        const char *entered_password = gtk_entry_get_text(GTK_ENTRY(password_entry));

        // hashing the entered password
        char entered_hash[65];
        sha256_string((char *)entered_password, entered_hash);

        FILE *file = fopen("master.hash", "r");
        if (!file)
        {
            printf("Master password not set. Please set the master password first.\n");
            return 0;
        }

        char stored_hash[65];
        fscanf(file, "%64s", stored_hash);
        fclose(file);

        // comparing stored hash and new hash
        if (strcmp(entered_hash, stored_hash) == 0)
        {
            printf("Master password verified successfully.\n");
            gtk_widget_destroy(password_dialog);
            return 1;
        }
        else
        {
            printf("Incorrect master password.\n");
        }
    }

    gtk_widget_destroy(password_dialog);
    return 0;
}

// Encrypt
void encrypt_password_flow(GtkWidget *widget, gpointer data)
{
    if (!verify_master_password(widget, data))
    {
        return;
    }

    GtkWidget *web_entry = (GtkWidget *)data;
    const char *website = gtk_entry_get_text(GTK_ENTRY(web_entry));

    char pass[1000];
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(gtk_widget_get_toplevel(web_entry)),
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_INFO,
                                               GTK_BUTTONS_OK_CANCEL,
                                               "Enter password for %s", website);

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Enter Password");

    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
                       entry, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);

    int response = gtk_dialog_run(GTK_DIALOG(dialog));
    if (response == GTK_RESPONSE_OK)
    {
        const char *password = gtk_entry_get_text(GTK_ENTRY(entry));
        strcpy(pass, password);

        XOR(pass, 7);

        FILE *file = fopen("encrypted_password.txt", "a");
        if (!file)
        {
            perror("Failed to open file");
            exit(EXIT_FAILURE);
        }

        fprintf(file, "%s ", website);
        for (int i = 0; pass[i] != '\0'; i++)
        {
            fprintf(file, "%02X", (unsigned char)pass[i]); //%02x for hex
        }
        fprintf(file, "\n");
        fclose(file);

        printf("Encrypted password saved to 'encrypted_password.txt'\n");
    }
    gtk_widget_destroy(dialog);
}

// Decrypt
void decrypt_password_flow(GtkWidget *widget, gpointer data)
{
    GtkWidget *web_entry = (GtkWidget *)data;
    const char *website = gtk_entry_get_text(GTK_ENTRY(web_entry));

    FILE *file = fopen("encrypted_password.txt", "r");
    if (!file)
    {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    char search_web[100], hex_pass[900];

    int found = 0;
    while (fgets(line, sizeof(line), file))
    {
        if (sscanf(line, "%99s %899s", search_web, hex_pass) == 2)
        {
            if (strcmp(search_web, website) == 0)
            {
                found = 1;
                break;
            }
        }
    }

    fclose(file);

    if (found)
    {
        int hex_len = strlen(hex_pass);
        int byte_len = hex_len / 2;
        unsigned char password_bytes[byte_len];

        hex_to_bytes(hex_pass, password_bytes, byte_len);
        XOR((char *)password_bytes, 7);

        printf("Decrypted password: ");
        for (int i = 0; i < byte_len; i++)
        {
            printf("%c", password_bytes[i]);
        }
        printf("\n");
    }
    else
    {
        printf("Website not found.\n");
    }
}

// hex to bytes
void hex_to_bytes(const char *hex, unsigned char *bytes, int len)
{
    for (int i = 0; i < len; i++)
    {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

static void on_master_password_entry(GtkWidget *widget, gpointer data)
{
    setup_master_password(widget, data);
}

int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Password Manager");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    // Master password set or not
    if (!verify_master_password(window, NULL))
    {
        GtkWidget *password_button = gtk_button_new_with_label("Set Master Password");
        g_signal_connect(password_button, "clicked", G_CALLBACK(on_master_password_entry), NULL);
        gtk_box_pack_start(GTK_BOX(vbox), password_button, TRUE, TRUE, 0);
    }

    // Website add n find
    GtkWidget *web_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(web_entry), "Enter Website");
    gtk_box_pack_start(GTK_BOX(vbox), web_entry, TRUE, TRUE, 0);

    GtkWidget *add_button = gtk_button_new_with_label("Add Password");
    g_signal_connect(add_button, "clicked", G_CALLBACK(encrypt_password_flow), (gpointer)web_entry);
    gtk_box_pack_start(GTK_BOX(vbox), add_button, TRUE, TRUE, 0);

    GtkWidget *find_button = gtk_button_new_with_label("Find Password");
    g_signal_connect(find_button, "clicked", G_CALLBACK(decrypt_password_flow), (gpointer)web_entry);
    gtk_box_pack_start(GTK_BOX(vbox), find_button, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(window), vbox);
    gtk_widget_show_all(window);

    gtk_main();
    return 0;
}
