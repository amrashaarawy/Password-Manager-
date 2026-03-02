/*Final code for password manager project of Computer Engineering.
 * 17/2/2026  Amr Shaarawy 2092459
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define DB_FILE "passwords.dat"
#define MASTER_FILE "master.bin"
#define DEFAULT_MASTER "Admin123"
#define FIELD_SIZE 50

// --- DATA STRUCTURE ---
typedef struct PasswordNode {
    char username[FIELD_SIZE];
    char domain[FIELD_SIZE];
    char password[FIELD_SIZE];
    struct PasswordNode *next;
} PasswordNode;

// --- FUNCTION PROTOTYPES ---
void encrypt_decrypt(char *data, int size);
void save_db(PasswordNode *head);
PasswordNode* load_db();
void save_master(char *new_master);
void load_master(char *master_dest);
void import_csv(PasswordNode **head_ref);
void export_csv(PasswordNode *head);
void generate_secure_password(char *dest, int length);
void analyze_strength(const char *pwd);
void add_node(PasswordNode **head_ref, char *user, char *dom, char *pass);
void free_list(PasswordNode *head);

// --- MAIN CONTROL LOOP ---
int main() {
    PasswordNode *head = NULL;
    char master_input[FIELD_SIZE], stored_master[FIELD_SIZE];
    int choice;

    load_master(stored_master);

    printf("--- Secure Password Manager ---\n");
    printf("Enter Master Password: ");
    scanf("%49s", master_input);

    if (strcmp(master_input, stored_master) != 0) {
        printf("Access Denied!\n");
        return 1;
    }

    head = load_db();

    while (1) {
        printf("\n--- MENU ---\n"
               "1. List All\n"
               "2. Add New\n"
               "3. Generate Password\n"
               "4. Change Master\n"
               "5. Import CSV\n"
               "6. Export CSV\n"
               "7. Clear Password Database & Exit\n"
               "8. Save & Exit\n"
               "Choice: ");

        if (scanf("%d", &choice) != 1) break;

        switch (choice) {
            case 1: {
                PasswordNode *curr = head;
                printf("\n%-15s %-15s %-10s\n", "User", "Domain", "Strength");
                while (curr) {
                    printf("%-15s %-15s ", curr->username, curr->domain);
                    analyze_strength(curr->password);
                    curr = curr->next;
                }
                break;
            }

            case 2: {
                char u[FIELD_SIZE], d[FIELD_SIZE], p[FIELD_SIZE];
                printf("User: ");   scanf("%49s", u);
                printf("Domain: "); scanf("%49s", d);
                printf("Pass: ");   scanf("%49s", p);
                add_node(&head, u, d, p);

                save_db(head); // autosave each entry
                printf("Saved.\n");
                break;
            }

            case 3: {
                char gen_p[20], u[FIELD_SIZE], d[FIELD_SIZE];
                generate_secure_password(gen_p, 14);
                printf("\nGenerated: %s\nSave? (y/n): ", gen_p);

                char c;
                scanf(" %c", &c);
                if (c == 'y' || c == 'Y') {
                    printf("User: ");   scanf("%49s", u);
                    printf("Domain: "); scanf("%49s", d);
                    add_node(&head, u, d, gen_p);

                    save_db(head); // autosave
                    printf("Saved.\n");
                }
                break;
            }

            case 4: {
                char current_try[FIELD_SIZE], new1[FIELD_SIZE], new2[FIELD_SIZE];

                printf("Enter Current Master: ");
                scanf("%49s", current_try);

                if (strcmp(current_try, stored_master) != 0) {
                    printf("Wrong master password. Update cancelled.\n");
                    break;
                }

                printf("Enter New Master: ");
                scanf("%49s", new1);
                printf("Re-enter New Master: ");
                scanf("%49s", new2);

                if (strcmp(new1, new2) != 0) {
                    printf("Mismatch. Update cancelled.\n");
                    break;
                }

                save_master(new1);
                strcpy(stored_master, new1);
                printf("Master password updated.\n");
                break;
            }

            case 5:
                import_csv(&head);
                save_db(head); // autosave after import
                printf("Imported and saved.\n");
                break;

            case 6:
                export_csv(head); // clear text export 
                break;

            case 7:
                remove(DB_FILE);
                free_list(head);
                printf("Database cleared.\n");
                return 0;

            case 8:
                save_db(head);
                free_list(head);
                printf("Saved and exited.\n");
                return 0;

            default:
                printf("Invalid choice.\n");
        }
    }

    free_list(head);
    return 0;
}

// --- LOGIC IMPLEMENTATIONS ---

void encrypt_decrypt(char *data, int size) {
    char key = 'K';
    for (int i = 0; i < size; i++) data[i] ^= key;  //symmetric enryption using XOR
}

void add_node(PasswordNode **head_ref, char *user, char *dom, char *pass) {
    PasswordNode *newNode = (PasswordNode*)malloc(sizeof(PasswordNode));
    if (!newNode) return;

    memset(newNode->username, 0, FIELD_SIZE);
    memset(newNode->domain, 0, FIELD_SIZE);
    memset(newNode->password, 0, FIELD_SIZE);

    strncpy(newNode->username, user, FIELD_SIZE - 1);
    strncpy(newNode->domain, dom, FIELD_SIZE - 1);
    strncpy(newNode->password, pass, FIELD_SIZE - 1);

    newNode->next = (*head_ref);
    (*head_ref) = newNode;
}

void free_list(PasswordNode *head) {
    PasswordNode *temp;
    while (head != NULL) {
        temp = head;
        head = head->next;
        free(temp);
    }
}

/*
 * ENCRYPTS THE WHOLE RECORD:
 * username + domain + password are encrypted on disk.
 */
void save_db(PasswordNode *head) {
    FILE *fp = fopen(DB_FILE, "wb");
    if (!fp) {
        printf("Error: could not open DB file for writing.\n");
        return;
    }

    int count = 0;
    PasswordNode *curr = head;
    while (curr) { count++; curr = curr->next; }

    if (fwrite(&count, sizeof(int), 1, fp) != 1) {
        printf("Error: failed to write DB header.\n");
        fclose(fp);
        return;
    }

    curr = head;
    while (curr) {
        // Encrypt ALL fields before writing
        encrypt_decrypt(curr->username, 50);
        encrypt_decrypt(curr->domain, 50);
        encrypt_decrypt(curr->password, 50);

        int ok =
            (fwrite(curr->username, 50, 1, fp) == 1) &&
            (fwrite(curr->domain, 50, 1, fp) == 1) &&
            (fwrite(curr->password, 50, 1, fp) == 1);

        // restore back to plaintext (even if write fails)
        encrypt_decrypt(curr->username, 50);
        encrypt_decrypt(curr->domain, 50);
        encrypt_decrypt(curr->password, 50);

        if (!ok) {
            printf("Error: failed to write DB record.\n");
            fclose(fp);
            return;
        }

        curr = curr->next;
    }

    fclose(fp);
}

/*
 * DECRYPTS THE WHOLE RECORD:
 * u + d + p are decrypted after reading.
 */
PasswordNode* load_db() {
    FILE *fp = fopen(DB_FILE, "rb");
    if (!fp) return NULL;

    int count;
    if (fread(&count, sizeof(int), 1, fp) != 1 || count < 0) {
        // header read failed or invalid
        fclose(fp);
        return NULL;
    }

    PasswordNode *head = NULL;

    for (int i = 0; i < count; i++) {
        char u[50], d[50], p[50];

        if (fread(u, 50, 1, fp) != 1 ||
            fread(d, 50, 1, fp) != 1 ||
            fread(p, 50, 1, fp) != 1) {
            printf("Warning: DB file seems corrupted or incomplete. Loaded %d/%d entries.\n", i, count);
            break;
        }

        // Decrypt all fields
        encrypt_decrypt(u, 50);
        encrypt_decrypt(d, 50);
        encrypt_decrypt(p, 50);

        // Guarantee valid C strings 
        u[49] = '\0';
        d[49] = '\0';
        p[49] = '\0';

        add_node(&head, u, d, p);
    }

    fclose(fp);
    return head;
}


void save_master(char *new_master) {
    FILE *fp = fopen(MASTER_FILE, "wb");
    if (!fp) {
        printf("Error: could not open master file for writing.\n");
        return;
    }

    char buf[FIELD_SIZE] = {0};
    strncpy(buf, new_master, FIELD_SIZE - 1);

    encrypt_decrypt(buf, FIELD_SIZE);

    if (fwrite(buf, 1, FIELD_SIZE, fp) != FIELD_SIZE) {
        printf("Error: failed to write master file.\n");
    }

    fclose(fp);
}

void load_master(char *master_dest) {
    FILE *fp = fopen(MASTER_FILE, "rb");
    if (!fp) {
        strcpy(master_dest, DEFAULT_MASTER);     //Uses default master for first use
        return;
    }

    if (fread(master_dest, 1, FIELD_SIZE, fp) != FIELD_SIZE) {
        fclose(fp);
        strcpy(master_dest, DEFAULT_MASTER);
        return;
    }

    encrypt_decrypt(master_dest, FIELD_SIZE);    //Decrypt master from secure file
    fclose(fp);
}

void generate_secure_password(char *dest, int length) {
    char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*";
    srand((unsigned int)time(NULL));
    for (int i = 0; i < length; i++) dest[i] = charset[rand() % (sizeof(charset) - 1)];
    dest[length] = '\0';
}

void import_csv(PasswordNode **head_ref) {
    char fname[FIELD_SIZE];
    printf("CSV Name: ");
    scanf("%49s", fname);

    FILE *fp = fopen(fname, "r");
    if (!fp) {
        printf("Error: could not open CSV file.\n");
        return;
    }

    char u[FIELD_SIZE], d[FIELD_SIZE], p[FIELD_SIZE];
    int imported = 0;

    while (fscanf(fp, " %49[^,],%49[^,],%49s", u, d, p) == 3) {  //parsing
        add_node(head_ref, u, d, p);
        imported++;
    }

    fclose(fp);
    printf("Imported %d entries.\n", imported);
}

void export_csv(PasswordNode *head) {
    FILE *fp = fopen("cleartext_export.csv", "w");
    if (!fp) {
        printf("Error: could not open export file.\n");
        return;
    }

    PasswordNode *curr = head;
    while (curr) {
        // RAM is plaintext, so export is clear text 
        fprintf(fp, "%s,%s,%s\n", curr->username, curr->domain, curr->password);
        curr = curr->next;
    }

    fclose(fp);
    printf("Exported to 'cleartext_export.csv'.\n");
}

void analyze_strength(const char *pwd) {
    int len = (int)strlen(pwd);
    if (len > 12) printf("[STRONG]\n");
    else if (len > 7) printf("[MEDIUM]\n");
    else printf("[WEAK]\n");
}
