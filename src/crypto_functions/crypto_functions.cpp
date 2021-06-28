#include "./crypto_functions.h"


using namespace std;


int sym_auth_encr(const EVP_CIPHER* cipher, unsigned char* pt, int pt_len, unsigned char* key, unsigned char* iv, unsigned char* aad, int aad_len, unsigned char* ct, int tag_len, unsigned char* tag){

    int ret = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CRYPTO_CHECK_ERROR(ctx);

    /* Encrypt init, it must be done only once */
    ret = EVP_EncryptInit(ctx, cipher, key, iv);
    CRYPTO_CHECK_ERROR(ret);

    int ct_len = 0;
    int written = 0;

    /* Aggiungo dati per authenticazione AAD */
    ret = EVP_EncryptUpdate(ctx, NULL, &written, aad, aad_len);
    CRYPTO_CHECK_ERROR(ret);

    /* Message encryption */
    ret = EVP_EncryptUpdate(ctx, ct, &written, pt, pt_len);
    CRYPTO_CHECK_ERROR(ret);

    /* Update ciphertext len */
    ct_len = ct_len + written;

    /* Encrypt Final, finalize the encryption and adds the padding */
    ret = EVP_EncryptFinal(ctx, ct + written, &written);
    CRYPTO_CHECK_ERROR(ret);

    /* Retrieves computed tag, and stores it in preallocated buffer tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag);

    ct_len = ct_len + written;

    /* Context free */
    EVP_CIPHER_CTX_free(ctx);

    return ct_len;
}



int sym_auth_decr(const EVP_CIPHER* cipher, unsigned char *ct, int ct_len, unsigned char *key, unsigned char *iv, unsigned char* aad, int aad_len, unsigned char *pt, int tag_len, unsigned char* tag){

    int ret = 0;
    int written = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CRYPTO_CHECK_ERROR(ctx);

    /* Decrypt init, it must be done only once */
    ret = EVP_DecryptInit(ctx, cipher, key, iv);
    CRYPTO_CHECK_ERROR(ret);

    /* Add authentication data AAD */
    ret = EVP_DecryptUpdate(ctx, NULL, &written, aad, aad_len);
    CRYPTO_CHECK_ERROR(ret);

    /* Decrypt Update*/
    ret = EVP_DecryptUpdate(ctx, pt, &written, ct, ct_len);
    CRYPTO_CHECK_ERROR(ret);

    /* Set received tag from buffer tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag);

    /* Decrypt Final, finalize the decryption and removes the padding */
    ret = EVP_DecryptFinal(ctx, pt + written, &written);
    if(ret == 0){ // tag mismatch
      return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return 1;

}



int dig_env_encr(const EVP_CIPHER* cipher, EVP_PKEY* public_key, unsigned char* pt, int pt_len, unsigned char* encrypted_sym_key, int encrypted_sym_key_len, unsigned char* iv, unsigned char* ct){

    int ret = 0;
    int outlen = 0;
    int ct_len = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CRYPTO_CHECK_ERROR(ctx);

    /* Generate the IV and the symmetric key and encrypt the symmetric key */
    ret = EVP_SealInit(ctx, cipher, &encrypted_sym_key, &encrypted_sym_key_len, iv, &public_key, 1);
    CRYPTO_CHECK_ERROR(ctx);

    /* Encrypt the plaintext */
    ret = EVP_SealUpdate(ctx, ct, &outlen, (unsigned char*)pt, pt_len);
    CRYPTO_CHECK_ERROR(ctx);
    ct_len = outlen;

    /* Finalize the encryption and add the padding */
    ret = EVP_SealFinal(ctx, ct + ct_len, &outlen);
    CRYPTO_CHECK_ERROR(ctx);
    ct_len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return ct_len;

}



int dig_env_decr(const EVP_CIPHER* cipher, EVP_PKEY* private_key, unsigned char* ct, int ct_len, unsigned char* encrypted_sym_key, int encrypted_sym_key_len, unsigned char* iv, unsigned char* pt){

    int ret = 0;
    int outlen = 0;
    int pt_len = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CRYPTO_CHECK_ERROR(ctx);

    /* Decrypt the symmetric key that will be used to decrypt the ciphertext */
    ret = EVP_OpenInit(ctx, cipher, encrypted_sym_key, encrypted_sym_key_len, iv, private_key);
    CRYPTO_CHECK_ERROR(ctx);

    /* Decrypt the ciphertext */
    ret = EVP_OpenUpdate(ctx, pt, &outlen, ct, ct_len);
    CRYPTO_CHECK_ERROR(ctx);
    pt_len += outlen;

    ret = EVP_OpenFinal(ctx, pt + pt_len, &outlen);
    CRYPTO_CHECK_ERROR(ctx);

    pt_len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return pt_len;

}



int dig_sign_sgn(const EVP_MD* md, EVP_PKEY* private_key, unsigned char* pt, int pt_len, unsigned char* sign){

    int ret = 0;

    /* Creating context */
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    CRYPTO_CHECK_ERROR(ctx);

    /* Initialized the context for digital signature */
    ret = EVP_SignInit(ctx, md);
    CRYPTO_CHECK_ERROR(ctx);

    /* Update the context */
    ret = EVP_SignUpdate(ctx, pt, pt_len);
    CRYPTO_CHECK_ERROR(ctx);

    /* Finalize the context and compute the digital signature */
    unsigned int sign_len = 0;
    ret = EVP_SignFinal(ctx, sign, &sign_len, private_key);
    CRYPTO_CHECK_ERROR(ctx);

    /* Context free */
    EVP_MD_CTX_free(ctx);

    return sign_len;

}



int dig_sign_verif( const EVP_MD* md,  EVP_PKEY* public_key, unsigned char* sign, int sign_size, unsigned char* pt, int pt_len){

    int ret = 0;

    // Create the signature context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    CRYPTO_CHECK_ERROR(md_ctx);

    // Initialize the contex to verify digital siganture
    ret = EVP_VerifyInit(md_ctx, md);
    CRYPTO_CHECK_ERROR(ret);

    // Update the context
    ret = EVP_VerifyUpdate(md_ctx, pt, pt_len);
    CRYPTO_CHECK_ERROR(ret);

    // Finalize the context and verify the signature
    int verification_result = EVP_VerifyFinal(md_ctx, sign, sign_size, public_key);

    EVP_MD_CTX_free(md_ctx);

    // Return the verification (0 if invalid signature, -1 if some other error, 1 if success)
    return verification_result;
}



int cert_verification(string CA_cert_filepath, string CA_CRL_filepath, X509* server_cert){

    int ret = 0;

    // Loading CA's certificate file
    FILE* CA_server_cert_file = fopen(CA_cert_filepath.c_str(), "r");
    CRYPTO_CHECK_ERROR(CA_server_cert_file);

    // Reading CA's certificate from file
    X509* CA_cert = PEM_read_X509(CA_server_cert_file, NULL, NULL, NULL);

    fclose(CA_server_cert_file);
    CRYPTO_CHECK_ERROR(CA_cert);

    // Loading CRL
    FILE* CRL_file = fopen(CA_CRL_filepath.c_str(), "r");
    CRYPTO_CHECK_ERROR(CRL_file);

    // Reading CRL from file
    X509_CRL* crl = PEM_read_X509_CRL(CRL_file, NULL, NULL, NULL);
    fclose(CRL_file);
    CRYPTO_CHECK_ERROR(crl);

    // Build a store with the CA's certificate and the CRL
    X509_STORE* store = X509_STORE_new();
    CRYPTO_CHECK_ERROR(store);

    // Adding CA's certificate to the store
    ret = X509_STORE_add_cert(store, CA_cert);
    CRYPTO_CHECK_ERROR(ret);

    // Adding CA's CRL to the store
    ret = X509_STORE_add_crl(store, crl);
    CRYPTO_CHECK_ERROR(ret);

    // Setting flag to use CRL
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    CRYPTO_CHECK_ERROR(ret);


    // Verify the peer's certificate
    X509_STORE_CTX* cert_verif_ctx = X509_STORE_CTX_new();
    CRYPTO_CHECK_ERROR(cert_verif_ctx);

    // Initialize the context for verfication
    ret = X509_STORE_CTX_init(cert_verif_ctx, store, server_cert, NULL);
    CRYPTO_CHECK_ERROR(ret);

    // Verify peer's certificate
    ret = X509_verify_cert(cert_verif_ctx);
    if(ret != 1) {
        cerr << "ERROR: X509_verify_cert fails!\n";
        return -1;
    }

    return 1;
}



unsigned char* generate_random_bytes(int len){

    int ret;

    // Seed OpenSSL PRNG
    RAND_poll();

    unsigned char* k = NULL;
    CHECK_MALLOC(k, len, -1);

    // Generates len random bytes
    ret = RAND_bytes((unsigned char*)&k[0], len);
    if(ret != 1){
        cerr << "ERROR: RAND_bytes fails!\n";
        return NULL;
    }

    return k;

}
