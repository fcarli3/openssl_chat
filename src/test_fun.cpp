#include "./crypto_functions/crypto_functions.cpp"



int main(){

    cout<<"\nTEST FUNCTIONS\n";
/*

    const EVP_CIPHER* cifrario = EVP_aes_128_gcm();

    unsigned char* plaintext = (unsigned char*) "Ciao sono Gianluca!";
    int plaintext_len = strlen((char*) plaintext);

    unsigned char* chiave = (unsigned char*) "1234567890";

    int iv_size = EVP_CIPHER_iv_length(cifrario);

    unsigned char* iv = (unsigned char*) malloc(iv_size);

    RAND_bytes((unsigned char*)&iv[0], iv_size);
    
    unsigned char* AAD = iv;
    int AAD_size = iv_size;


    int ct_len = EVP_CIPHER_block_size(cifrario) + plaintext_len;
    unsigned char* ciphertext = (unsigned char*) malloc(ct_len);
    unsigned char* tag = (unsigned char*) malloc(16);


    int ct_real_size = Sym_Auth_Encr(cifrario, plaintext, plaintext_len, chiave, iv, AAD, AAD_size, ciphertext, 16, tag);

    cout<<"\npt: "<<plaintext;
    cout<<"\nct: ";
    BIO_dump_fp(stdout, (const char*) ciphertext, ct_real_size);



    unsigned char* decifrato = (unsigned char*) malloc(plaintext_len);
    Sym_Auth_Decr(cifrario, ciphertext, ct_real_size, chiave, iv, AAD, AAD_size, decifrato, 16, tag);

    cout<<"\n\n\ndecifrato: "<<decifrato<<"\n";


    cout<<"**********************************\n";


    //leggo chiave pubblica
    EVP_PKEY* pub_key = read_pub_key("giallu_public_key.pem");


    

    //cifro
    unsigned char* plaintext = (unsigned char*) "Ciao sono GFP!";
    int plaintext_len = strlen((char*)plaintext);
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int blk_size = EVP_CIPHER_block_size(cipher);

    int encrypted_sym_key_len = EVP_PKEY_size(pub_key);
    unsigned char* encr_sym_key = (unsigned char*) malloc(encrypted_sym_key_len);
    unsigned char* ct_rsa = (unsigned char*) malloc(plaintext_len + blk_size);

    unsigned char* iv_rsa = (unsigned char*) malloc(EVP_CIPHER_iv_length(cipher));

    int ct_rsa_len = Dig_Env_Encr(cipher, pub_key, plaintext, plaintext_len, encr_sym_key, encrypted_sym_key_len, iv_rsa, ct_rsa);




    //leggo chiave privata 
    EVP_PKEY* priv_key = read_private_key("giallu_private_key.pem");

    unsigned char* decifrato_rsa = (unsigned char*) malloc(plaintext_len+1);
    int real_size_pt = Dig_Env_Decr(cipher, priv_key, ct_rsa, ct_rsa_len, encr_sym_key, encrypted_sym_key_len, iv_rsa, decifrato_rsa);



    cout<<"\n LEN:"<<strlen((char*)decifrato_rsa);
    cout<<"\ndecifrato: "<<decifrato_rsa<<"--\n";


    
    //RSA private key encryption (Digital Signature)
    
    EVP_PKEY* priv_key = read_private_key("giallu_private_key.pem");
    unsigned char* pt = (unsigned char*) "Ciao sono GFP!";
    int pt_len = strlen((char*)pt);
    const EVP_MD* algo_firma = EVP_sha256(); //DA CONTROLLARE
    unsigned char* firma = (unsigned char*) malloc(EVP_PKEY_size(priv_key));

    int firma_len = Dig_Sign_sgn(algo_firma, priv_key, pt, pt_len, firma);



    
    EVP_PKEY* pub_key = read_pub_key("giallu_public_key.pem");
    firma[2]='g';
    int res = Dig_Sign_verif(algo_firma, pub_key, firma, firma_len, pt, pt_len);
    
    if(res == 1){cout<<"\nVERIFICA CON SUCCESSO\n";}
    else{
        if(res == 0) {cout<<"\nFIRMA NON COINCIDE\n";}
        else{cout<<"\nERRORE\n";}
    }
    
*/


    if(Cert_verification("CA_cert.pem", "CA_revocation_list.pem", "Server_ChatApp_certificate.pem")){
        cout<<"\nCERTIFICATO OK\n";
    }
    else{
        cout<<"\nCERTIFICATO FAKE\n";
    }
    

}