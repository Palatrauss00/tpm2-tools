#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <tss2/tss2_sys.h>

#define MESSAGE "Hello, Quantum Safe World!"

// Funzione per sigillare la chiave nel TPM
void seal_key_in_tpm(const char *key_data, const char *key_file) {
    FILE *fp = fopen(key_file, "w");
    if (fp) {
        fprintf(fp, "%s", key_data);
        fclose(fp);
    } else {
        perror("Failed to open file for sealing");
        exit(EXIT_FAILURE);
    }

    // Esegui i comandi TPM
    system("tpm2_createprimary -C o -c primary.ctx");
    system("tpm2_create -C primary.ctx -u key.pub -r key.priv -i key_file -c key.ctx");
    system("tpm2_flushcontext --transient-object");
}

// Funzione per decrittografare la chiave dal TPM
void unseal_key_from_tpm() {
    system("tpm2_unseal -c key.ctx > unsealed_key");
}

// Funzione principale
int main() {
    // Inizializzazione di liboqs
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == NULL) {
        fprintf(stderr, "Error initializing OQS KEM\n");
        return EXIT_FAILURE;
    }

    // Generazione di chiavi quantistiche
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error generating key pair\n");
        return EXIT_FAILURE;
    }

    // Sigillare la chiave segreta nel TPM
    seal_key_in_tpm((const char *)secret_key, "secret.key");

    // Eseguire l'incapsulamento (cifratura)
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error during encapsulation\n");
        return EXIT_FAILURE;
    }

    // Verifica la crittografia
    printf("Encrypted data: ");
    for (size_t i = 0; i < kem->length_ciphertext; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Unseal the secret key from the TPM
    unseal_key_from_tpm();

    // Decrypt the shared secret
    // (Assuming secret_key has been read from unsealed_key)
    uint8_t *unsealed_secret_key = malloc(kem->length_secret_key);
    FILE *key_fp = fopen("unsealed_key", "r");
    fread(unsealed_secret_key, sizeof(uint8_t), kem->length_secret_key, key_fp);
    fclose(key_fp);

    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, unsealed_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error during decapsulation\n");
        return EXIT_FAILURE;
    }

    // Verifica la decapsulazione
    printf("Shared secret: ");
    for (size_t i = 0; i < kem->length_shared_secret; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");

    // Pulizia
    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret);
    free(unsealed_secret_key);

    return EXIT_SUCCESS;
}
