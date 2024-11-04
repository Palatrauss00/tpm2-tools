#include <stdio.h>
#include <oqs/oqs.h>
#include <tss2/tss_esys.h>

#define TPM_KEY_FILE "kyber512_key.dat"
#define TPM_KEY_CTX "primary.ctx"

int initialize_tpm_context(ESYS_CONTEXT **ctx) {
    TSS2_RC r;
    r = Esys_Initialize(ctx, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Errore durante l'inizializzazione del contesto TPM.\n");
        return 1;
    }
    return 0;
}

int generate_pq_key(unsigned char **public_key, unsigned char **secret_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_kyber512);
    if (sig == NULL) {
        fprintf(stderr, "Errore durante la creazione dell'algoritmo Kyber512.\n");
        return 1;
    }

    *public_key = malloc(sig->length_public_key);
    *secret_key = malloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, *public_key, *secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Errore durante la generazione della coppia di chiavi.\n");
        OQS_SIG_free(sig);
        return 1;
    }

    OQS_SIG_free(sig);
    return 0;
}

int import_key_to_tpm(ESYS_CONTEXT *ctx, const unsigned char *public_key) {
    char command[512];
    snprintf(command, sizeof(command),
             "tpm2_import -C %s -G rsa -i %s -u kyber512_key.pub -r kyber512_key.priv",
             TPM_KEY_CTX, TPM_KEY_FILE);
    int status = system(command);
    if (status != 0) {
        fprintf(stderr, "Errore durante l'importazione della chiave nel TPM.\n");
        return 1;
    }
    return 0;
}

int sign_message_with_tpm(ESYS_CONTEXT *ctx, const char *message) {
    char command[512];
    snprintf(command, sizeof(command),
             "echo \"%s\" > message.dat && tpm2_sign -c kyber512_key.pub -g sha256 -m message.dat -f plain -s signature.dat",
             message);
    int status = system(command);
    if (status != 0) {
        fprintf(stderr, "Errore durante la firma del messaggio con TPM.\n");
        return 1;
    }
    return 0;
}

int main() {
    ESYS_CONTEXT *ctx;
    unsigned char *public_key = NULL, *secret_key = NULL;

    if (initialize_tpm_context(&ctx) != 0){
        return 1;
    }

    if (generate_pq_key(&public_key, &secret_key) != 0 ){
        Esys_Finalize(&ctx);
        return 1;
    }

    FILE *key_file = fopen("TPM_KEY_FILE", "wb");
    if (!key_file){
        fprintf(stderr, "Errore durante la creazione del file di chiave.\n");
        free(public_key);
        free(secret_key);
        Esys_Finalize(&ctx);
        return 1;
    }

    const char *message = "Messaggio di test per firma TPM";
    if(sign_message_with_tpm(ctx, message) != 0){
        free(public_key);
        free(secret_key);
        Esys_Finalize(&ctx);
        return 1;
    }

    printf("Firma completata. Controlla 'signature.dat' per la firma generata.\n");
    free(public_key);
    free(secret_key);
    Esys_Finalize(&ctx);

    return 0;
}