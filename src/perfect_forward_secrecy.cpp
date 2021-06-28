#include "perfect_forward_secrecy.h"
#include "./server/src/list_functions.cpp"


// Used by client
int send_random_nonce(long sock, string usr_name){

    int ret = 0;

    // Nonce (to avoid replay attack)
    int R = rand();

    // Convert int to unsigned char
    unsigned char* r_byte = NULL;
    CHECK_MALLOC(r_byte, sizeof(int), sock);
    int_to_byte(R, r_byte);

    // Create buffer to send the message
    int msg_len = HEADER_LEN + sizeof(int) + strlen(usr_name.c_str());
    unsigned char* msg_buff = NULL;
    CHECK_MALLOC(msg_buff, msg_len, sock);


    // Convert int to unsigned char
    int payload_len = sizeof(int) + strlen(usr_name.c_str());
    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
    int_to_byte(payload_len, payload_len_byte);


    // Create the message to send
    msg_buff[0] = MSG_TYPE_NONCE;
    memcpy(&msg_buff[1], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN], r_byte, sizeof(int));
    copy(usr_name.begin(), usr_name.end(), &msg_buff[HEADER_LEN + sizeof(int)]);


    // Send the message
    ret = sendn(sock, msg_buff, msg_len);
    C_CHECK_ERROR_INT(ret, sock);

    FREE3(r_byte, msg_buff, payload_len_byte);

    return R;
}


// Used by server
string read_nonce(long sock, int* nonce){

    int ret = 0;

    // Reading message header (msg_type + payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN);
    S_CHECK_ERROR_INT(ret, "ERR");


    // Error in case of mismatch of message type
    if(rcv_buff[0] != MSG_TYPE_NONCE){
        cout<<"\nError: invalid message type in read_nonce"<<endl;
        free(rcv_buff);
        return "ERR";
    }

    int payload_dim = 0;
    memcpy(&payload_dim, &rcv_buff[1], sizeof(int)); //Converting byte to int

    // Reading the payload: reading the nonce
    unsigned char* rcv_payload_nonce = NULL;
    CHECK_MALLOC(rcv_payload_nonce, sizeof(int), sock);
    ret = readn(sock, rcv_payload_nonce, sizeof(int));
    S_CHECK_ERROR_INT(ret, "ERR");

    // Reading the usrname
    int usrname_len = payload_dim - sizeof(int) + 1;
    unsigned char* rcv_usrname = NULL;
    CHECK_MALLOC(rcv_usrname, usrname_len, sock);
    memset(rcv_usrname, '\0', usrname_len);
    ret = readn(sock, rcv_usrname, usrname_len - 1);
    S_CHECK_ERROR_INT(ret, "ERR");

    // Converting nonce from byte to int
    memcpy(nonce, rcv_payload_nonce, sizeof(int)); //Converting byte to int

    //Converting name from byte to string
    string usr_name = (char*) rcv_usrname;

    FREE3(rcv_buff, rcv_usrname, rcv_payload_nonce);

    return usr_name;

}


// Generate and return RSA ephemeral keys
void generate_ephemeral_keys(EVP_PKEY** prv, EVP_PKEY** pub) {

    RSA *rsa = NULL;
    BIGNUM* big_num = NULL;
    BIO *bio = NULL;
    BIO *bio_pub = NULL;


    // Generate RSA key
    big_num = BN_new();
    BN_set_word(big_num, RSA_F4);
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, big_num, NULL);
    BN_free(big_num);


    // Extract the private key from rsa struct
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_read_bio_PrivateKey(bio, &(*prv), NULL, NULL);
    BIO_free_all(bio);


    // Extract the public key from the private key
    bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, *prv);
    PEM_read_bio_PUBKEY(bio_pub, &(*pub), NULL, NULL);
    BIO_free_all(bio_pub);

}


// Used by server
bool send_ephemeral_public_key(long sock, EVP_PKEY* ephemeral_pub_key, int nonce){

    int ret = 0;

    // Reading server private key
    EVP_PKEY* priv_key = read_private_key(SERVER_PRIV_KEY_PATH);
    if(priv_key == NULL){
      cout<<"\nError in send_ephemeral_public_key because of read_private_key"<<endl;
      return false;
    }


    // Converting nonce to byte
    unsigned char* nonce_byte = NULL;
    CHECK_MALLOC(nonce_byte, sizeof(int), sock);
    int_to_byte(nonce, nonce_byte);

    // Serialize the client ephemeral public key
    int eph_key_len = 0;
    unsigned char* client_eph_pub_key = get_public_key_to_byte(ephemeral_pub_key, &eph_key_len);
    if(client_eph_pub_key == NULL){
      cout<<"\nError in send_ephemeral_public_key because of get_public_key_to_byte"<<endl;
      return false;
    }


    // Converting eph_key_len from in to byte
    unsigned char* eph_key_len_byte = NULL;
    CHECK_MALLOC(eph_key_len_byte, sizeof(int), sock);
    int_to_byte(eph_key_len, eph_key_len_byte);


    // Create the message to sign (R||eph_pub_key)
    int msg_to_sign_len = sizeof(int) + eph_key_len;
    unsigned char* msg_to_sign = NULL;
    CHECK_MALLOC(msg_to_sign, msg_to_sign_len, sock);
    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) client_eph_pub_key, eph_key_len);


    // Sign the message
    int sign_len = EVP_PKEY_size(priv_key);
    unsigned char* sign = NULL;
    CHECK_MALLOC(sign, sign_len, sock);
    sign_len = dig_sign_sgn(SIGNATURE_ALGORITHM, priv_key, msg_to_sign, msg_to_sign_len, sign);
    if(sign_len == -10){
      cout<<"Error: invalid signature generation in send_ephemeral_public_key."<<endl;
      return false;
    }

    // Converting sign_len to byte
    unsigned char* sign_len_byte = NULL;
    CHECK_MALLOC(sign_len_byte, sizeof(int), sock);
    int_to_byte(sign_len, sign_len_byte);

    // Read server certificate
    int cert_len = -1;
    unsigned char* cert = read_certificate(SERVER_CERT_PATH, &cert_len);
    if(cert == NULL){
      cout<<"\nError in send_ephemeral_public_key because of read_certificate"<<endl;
      return false;
    }

    // Converting payload_len to byte
    int payload_len = sizeof(int) + sign_len + sizeof(int) + eph_key_len + cert_len;
    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
    int_to_byte(payload_len, payload_len_byte);


    // Create the buffer to send
    int msg_len = HEADER_LEN + payload_len;
    unsigned char* msg = NULL;
    CHECK_MALLOC(msg, msg_len, sock);

    msg[0] = MSG_TYPE_EPH_PUBKEY;
    memcpy((unsigned char*) &msg[1], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int)], sign, sign_len);
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len], eph_key_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int)], client_eph_pub_key, eph_key_len);
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + eph_key_len], cert, cert_len);


    // Send the buffer
    ret = sendn(sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);


    FREE5(nonce_byte, client_eph_pub_key, msg_to_sign, sign, sign_len_byte);
    FREE4(payload_len_byte, msg, cert, eph_key_len_byte);
    EVP_PKEY_free(priv_key);

    return true;

}


// Used by client
EVP_PKEY* read_ephemeral_public_key(long sock, int nonce){

    int ret = 0;

    // Reading message header (msg_type + payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN);
    C_CHECK_ERROR_INT(ret, sock);


    // Reading payload len
    int payload_dim = 0;
    memcpy(&payload_dim, &rcv_buff[1], sizeof(int)); //Converting byte to int

    // Error in case of mismatch of message type
    if(rcv_buff[0] != MSG_TYPE_EPH_PUBKEY){
        cout<<"\nError: invalid message type in read_ephemeral_public_key."<<endl;
        free(rcv_buff);
        return NULL;
    }


    // Reading the payload: reading signature len
    unsigned char* sign_len_byte = NULL;
    CHECK_MALLOC(sign_len_byte, sizeof(int), sock);
    ret = readn(sock, sign_len_byte, sizeof(int));
    C_CHECK_ERROR_INT(ret, sock);
    int sign_dim = 0;
    memcpy(&sign_dim, sign_len_byte, sizeof(int)); //Converting byte to int


    //Reading the payload: reading signature
    unsigned char* buff_sign = NULL;
    CHECK_MALLOC(buff_sign, sign_dim, sock);
    ret = readn(sock, buff_sign, sign_dim);
    C_CHECK_ERROR_INT(ret, sock);


    //Reading the payload: reading public key len
    unsigned char* eph_pubkey_byte = NULL;
    CHECK_MALLOC(eph_pubkey_byte, sizeof(int), sock);
    ret = readn(sock, eph_pubkey_byte, sizeof(int));
    C_CHECK_ERROR_INT(ret, sock);
    int eph_pubkey_len = -1;
    memcpy(&eph_pubkey_len, eph_pubkey_byte, sizeof(int));


    // Reading the public key
    unsigned char* buff_eph_key = NULL;
    CHECK_MALLOC(buff_eph_key, eph_pubkey_len, sock);
    ret = readn(sock, buff_eph_key, eph_pubkey_len);
    C_CHECK_ERROR_INT(ret, sock);


    // Reading server certificate
    int cert_len = payload_dim - eph_pubkey_len - sign_dim - sizeof(int)*2;
    unsigned char* buff_cert = NULL;
    CHECK_MALLOC(buff_cert, cert_len, sock);
    ret = readn(sock, buff_cert, cert_len);
    C_CHECK_ERROR_INT(ret, sock);


    // Verify the certificate
    X509* cert = deserialize_cert(buff_cert, cert_len);
    if(cert == NULL){
      cout<<"\nError in read_ephemeral_public_key because of deserialize_cert"<<endl;
      return NULL;
    }

    int result = cert_verification(CA_CERT_FILE_PATH, CA_CRL_FILE_PATH, cert);
    if(result == 1){
        print_Server_cert_info(cert);
    }
    else{
        cout<<"\Error: invalid certificate verification in read_ephemeral_public_key"<<endl;
        return NULL;
    }


    // Extract the long-term public key of server from certificate
    EVP_PKEY* server_pub_key = X509_get_pubkey(cert);
    if(server_pub_key == NULL){
      cout<<"\nError in read_ephemeral_public_key because of X509_get_pubkey"<<endl;
      return NULL;
    }


    // Create the plaintext (nonce||eph_pubkey) to verify the signature
    int signature_pt_len = sizeof(int) + eph_pubkey_len;
    unsigned char* signature_pt = NULL;
    CHECK_MALLOC(signature_pt, signature_pt_len, sock);
    unsigned char* nonce_byte = NULL;
    CHECK_MALLOC(nonce_byte, sizeof(int), sock);
    int_to_byte(nonce, nonce_byte);
    memcpy(signature_pt, nonce_byte, sizeof(int));
    memcpy(&signature_pt[sizeof(int)], buff_eph_key, eph_pubkey_len);


    // Verify the signature
    int res = dig_sign_verif(SIGNATURE_ALGORITHM, server_pub_key, buff_sign, sign_dim, signature_pt, signature_pt_len);
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = get_public_key_to_PKEY(buff_eph_key, eph_pubkey_len);
        if(p == NULL){
          return NULL;
        }
    } else {
      cout<<"\nError: invalid signature verification in read_ephemeral_public_key, (result error:"<<res<<")"<<endl;
      return NULL;
    }


    FREE5(rcv_buff, sign_len_byte, buff_sign, eph_pubkey_byte, buff_eph_key);
    FREE3(buff_cert, signature_pt, nonce_byte);
    EVP_PKEY_free(server_pub_key);

    return p;

}


// Used by client
bool send_session_key(long sock, unsigned char* session_key, EVP_PKEY* eph_pubkey, string usr_name){

    int ret = 0;

    // Encrypt the session key with the ephemeral public key
    int encrypted_symkey_len = EVP_PKEY_size(eph_pubkey);
    unsigned char* encrypted_symkey = NULL;
    CHECK_MALLOC(encrypted_symkey, encrypted_symkey_len, sock);

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_EXCHANGE_K_SESS);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);

    int session_key_len = EVP_CIPHER_key_length(SYMMETRIC_CIPHER_EXCHANGE_K_SESS);
    int ct_len = session_key_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_EXCHANGE_K_SESS);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);

    ct_len = dig_env_encr(SYMMETRIC_CIPHER_EXCHANGE_K_SESS, eph_pubkey, session_key, session_key_len, encrypted_symkey, encrypted_symkey_len, iv, ct);
    if(ct_len == -10){
      cout<<"Error: invalid encryption in send_session_key"<<endl;
      return false;
    }


    // Reading client private key
    string privkey_path = "./../" + usr_name + "_private_key.pem";
    EVP_PKEY* client_private_key = read_private_key(privkey_path);
    C_CHECK_ERROR(client_private_key, sock);


    // Buffer for signature
    int sign_len = EVP_PKEY_size(client_private_key);
    unsigned char* sign = NULL;
    CHECK_MALLOC(sign, sign_len, sock);


    //Convert eph public key to byte
    int eph_pubkey_len = -1;
    unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);


    // Create the plaintext to sign ( {session_key}_ephPubkey || ephPubkey )
    int pt_to_sign_len = eph_pubkey_len + ct_len;
    unsigned char* pt_to_sign = NULL;
    CHECK_MALLOC(pt_to_sign, pt_to_sign_len, sock);
    memcpy(pt_to_sign, ct, ct_len);
    memcpy(&pt_to_sign[ct_len], eph_pubkey_byte, eph_pubkey_len);


    // Create the signature
    sign_len = dig_sign_sgn(SIGNATURE_ALGORITHM, client_private_key, pt_to_sign, pt_to_sign_len, sign);
    if(sign_len == -10){
      cout<<"Error: invalid signature generation in send_session_key"<<endl;
      return false;
    }


    // Create the message to send
    int msg_len = HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len + iv_len;
    unsigned char* msg_buff = NULL;
    CHECK_MALLOC(msg_buff, msg_len, sock);


    // Convert payload_len from int to byte
    int payload_len = msg_len - HEADER_LEN;
    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
    int_to_byte(payload_len, payload_len_byte);


    // Convert sign_len from int to byte
    unsigned char* sign_len_byte = NULL;
    CHECK_MALLOC(sign_len_byte, sizeof(int), sock);
    int_to_byte(sign_len, sign_len_byte);


    // Convert ct_len from int to byte
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    int_to_byte(ct_len, ct_len_byte);


    // Convert encrypted_symkey_len from int to byte
    unsigned char* encrypted_symkey_len_byte = NULL;
    CHECK_MALLOC(encrypted_symkey_len_byte, sizeof(int), sock);
    int_to_byte(encrypted_symkey_len, encrypted_symkey_len_byte);


    // Create the buffer to send
    msg_buff[0] = MSG_TYPE_SESSION_KEY;
    memcpy(&msg_buff[1], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int)], (unsigned char*) sign, sign_len);
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len], (unsigned char*) encrypted_symkey_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int)], (unsigned char*) encrypted_symkey, encrypted_symkey_len);
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len], (unsigned char*) iv, iv_len);


    // Send the message
    ret = sendn(sock, msg_buff, msg_len);
    C_CHECK_ERROR_INT(ret, sock);

    FREE5(sign, encrypted_symkey, iv, ct, msg_buff);
    FREE3(sign_len_byte, payload_len_byte, ct_len_byte);
    EVP_PKEY_free(client_private_key);

    return true;

}


// Used by server
unsigned char* read_session_key(long sock, EVP_PKEY* eph_priv_key, EVP_PKEY* eph_pubkey, string usr_name, int* session_key_len){

    int ret = 0;

    // Reading message header (msg_type + payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN);
    S_CHECK_ERROR_INT(ret, NULL);

    // Error in case of mismatch of message type
    if(rcv_buff[0] != MSG_TYPE_SESSION_KEY){
        cout<<"\nError: invalid message type in read_session_key."<<endl;
        free(rcv_buff);
        return NULL;
    }

    int payload_dim = 0;
    memcpy(&payload_dim, &rcv_buff[1], sizeof(int)); //Converting byte to int


    // Reading the payload: signature_len
    unsigned char* sign_len_byte = NULL;
    CHECK_MALLOC(sign_len_byte, sizeof(int), sock);
    ret = readn(sock, sign_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, NULL);


    // Converting signature_len to int
    int sign_len = 0;
    memcpy(&sign_len, sign_len_byte, sizeof(int)); //Converting byte to int


    // Reading the payload: reading signature
    unsigned char* sign = NULL;
    CHECK_MALLOC(sign, sign_len, sock);
    ret = readn(sock, sign, sign_len);
    S_CHECK_ERROR_INT(ret, NULL);


    // Reading the payload: reading ct len
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    ret = readn(sock, ct_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, NULL);


    // Converting ct len from byte to int
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int));


    // Reading the ct
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);
    ret = readn(sock, ct, ct_len);
    S_CHECK_ERROR_INT(ret, NULL);


    // 1. Verify the signature : create the pt to verify  ( ct||eph_pubkey )
    int eph_pubkey_len = -1;
    unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);
    if(eph_pubkey_byte == NULL){
      cout<<"\nError: eph_pubkey_byte is null in read_session_key"<<endl;
      return NULL;
    }

    int pt_to_verify_len = ct_len + eph_pubkey_len;
    unsigned char* pt_to_verify = NULL;
    CHECK_MALLOC(pt_to_verify, pt_to_verify_len, sock);
    memcpy(pt_to_verify, ct, ct_len);
    memcpy(&pt_to_verify[ct_len], eph_pubkey_byte, eph_pubkey_len);


    // 1. Verify the signature: verification
    string client_pubkey_path = "./../pub_keys/" + usr_name + "_public_key.pem";
    EVP_PKEY* client_public_key = read_pub_key(client_pubkey_path);
    if(client_public_key == NULL){
      cout<<"\nError: client_public_key is null in read_session_key"<<endl;
      return NULL;
    }
    int result = dig_sign_verif(SIGNATURE_ALGORITHM, client_public_key, sign, sign_len, pt_to_verify, pt_to_verify_len);
    if(result == 0){
        cout<<"\nError: invalid signature verification in read_session_key"<<endl;;
        return NULL;
    }
    else{
        if(result == -1 || result == -10){
            cout<<"\n Error: error on signature verification OpenSSL API in read_session_key!"<<endl;;
            return NULL;
        }
    }


    // Reading the payload: reading encrypted symkey len
    unsigned char* encrypted_symkey_len_byte = NULL;
    CHECK_MALLOC(encrypted_symkey_len_byte, sizeof(int), sock);
    ret = readn(sock, encrypted_symkey_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, NULL);


    // Converting encrypted symkey len from byte to int
    int encrypted_symkey_len = -1;
    memcpy(&encrypted_symkey_len, encrypted_symkey_len_byte, sizeof(int));


    // Reading the payload: reading encrypted symkey
    unsigned char* encrypted_symkey_byte = NULL;
    CHECK_MALLOC(encrypted_symkey_byte, encrypted_symkey_len, sock);
    ret =readn(sock, encrypted_symkey_byte, encrypted_symkey_len);
    S_CHECK_ERROR_INT(ret, NULL);


    // Reading the payload: reading iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_EXCHANGE_K_SESS);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);
    ret = readn(sock, iv, iv_len);
    S_CHECK_ERROR_INT(ret, NULL);


    // Decrypt the session key with client private ephemeral key
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, ct_len, sock);
    *session_key_len = dig_env_decr(SYMMETRIC_CIPHER_EXCHANGE_K_SESS, eph_priv_key, ct, ct_len, encrypted_symkey_byte, encrypted_symkey_len, iv, pt);
    if(*session_key_len == -10){
      cout<<"\nError: invalid digital envelope decryption in read_session_key"<<endl;
      return NULL;
    }


    FREE5(rcv_buff, sign_len_byte, sign, ct_len_byte, ct);
    free(iv);
    EVP_PKEY_free(client_public_key);

    return pt;

}


// Used by client
int send_M_1_1(long sock, unsigned char* session_key, unsigned int* cont){

    int ret = 0;

    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);
    pt[0] = DUMMY_BYTE;


    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError: iv is null in send_M_1_1"<<endl;
      return -1;
    }


    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);


    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, tag_len, sock);


    unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
    int_to_byte((*cont), cont_byte);
    *cont = *cont + 1;


    // Create aad (msg_type || cont_client_server)
    int aad_len = 1 + sizeof(int) + sizeof(int);
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);


    unsigned char* nonce_byte = NULL;
    CHECK_MALLOC(nonce_byte, sizeof(int), sock);
    int nonce = rand();
    int_to_byte(nonce, nonce_byte);


    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_NONCE;


    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int)], nonce_byte, sizeof(int));


    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError: invalid encryption in send_M_1_1."<<endl;
      return -1;
    }

    // Create the message to send
    int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_LEN_SESSION;


    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
    int_to_byte(payload_len, payload_len_byte);


    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(int));
    int_to_byte(ct_len, ct_len_byte);


    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    int_to_byte(aad_len, aad_len_byte);


    // Create the buffer to send
    unsigned char* msg = NULL;
    CHECK_MALLOC(msg, msg_len, sock);
    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);


    ret = sendn(sock, msg, msg_len);
    C_CHECK_ERROR_INT(ret, sock);


    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);

    return nonce;


}


// Used by server
bool read_and_forward_M_1_1(string usr_name, string usr_2){

  int ret = 0;

  // <><><><><><><><><><><><> Phase 1: read from client 1 (usr_name) <><><><><><><><><><><><>

  long sock = get_usr_socket(usr_name);
  if(sock == -1){
    cout<<"\nError: invalid socket in read_and_forward_M_1_1"<<endl;
    return false;
  }


  unsigned char* session_key = get_usr_session_key(usr_name);
  if(session_key == NULL){
    cout<<"\nError: invalid session_key in read_and_forward_M_1_1"<<endl;
    return false;
  }


  unsigned int cont_cs = get_usr_cont_cs(usr_name);


  // Reading message header (payload_len)
  unsigned char* rcv_buff = NULL;
  CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
  ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
  S_CHECK_ERROR_INT(ret, false);
  int payload_dim = 0;
  memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


  // Read aad_len and aad
  unsigned char* aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  ret = readn(sock, aad_len_byte, sizeof(int));
  S_CHECK_ERROR_INT(ret, false);

  int aad_len = 0;
  memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);
  ret = readn(sock, aad, aad_len);
  S_CHECK_ERROR_INT(ret, false);


  // Read ct_len and ct
  unsigned char* ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
  ret = readn(sock, ct_len_byte, sizeof(int));
  S_CHECK_ERROR_INT(ret, false);

  int ct_len = 0;
  memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

  unsigned char* ct = NULL;
  CHECK_MALLOC(ct, ct_len, sock);
  ret = readn(sock, ct, ct_len);
  S_CHECK_ERROR_INT(ret, false);


  // Read tag
  unsigned char* tag = NULL;
  CHECK_MALLOC(tag, TAG_LEN, sock);
  ret = readn(sock, tag, TAG_LEN);
  S_CHECK_ERROR_INT(ret, false);


  // Read iv
  int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
  unsigned char* iv = NULL;
  CHECK_MALLOC(iv, iv_len, sock);
  ret = readn(sock, iv, iv_len);
  S_CHECK_ERROR_INT(ret, false);


  // Read msg_type
  char msg_type = (char) aad[0];
  if(MSG_TYPE_NONCE != msg_type){
      cout<<"\nError: invalid message type in read_and_forward_M_1_1"<<endl;
      return false;
  }


  //Check the counter
  unsigned int rcv_cont = 0;
  memcpy(&rcv_cont, &aad[1], sizeof(int));
  if(rcv_cont != cont_cs){
      cout<<"\nError: invalid cont in read_and_forward_M_1_1"<<endl;
      return false;
  }
  increase_usr_cont_cs(usr_name);


  // Decrypt the ciphertext
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, ct_len, sock);
  int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
  if(result == -10 || result == -1){
    cerr<<"\nError: invalid decryption in read_and_forward_M_1_1, (error result: "<<result<<")"<<endl;
    return false;
  }


  // Get the nonce from aad
  unsigned char* nonce_byte = NULL;
  CHECK_MALLOC(nonce_byte, sizeof(int), sock);
  memcpy(nonce_byte, &aad[1 + sizeof(int)], sizeof(int));



  // <><><><><><><><><><><><> Phase 2: forward from client 1 (usr_name) to client 2 (usr_2) <><><><><><><><><><><><>


  // Encrypt the plaintext
  int pt_len = 1;

  free(iv);
  iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
  iv = generate_random_bytes(iv_len);
  if(iv == NULL){
    cout<<"\nError: invalid iv in read_and_forward_M_1_1"<<endl;
    return false;
  }


  free(ct);
  ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
  ct = NULL;
  CHECK_MALLOC(ct, ct_len, sock);


  free(tag);
  tag = NULL;
  CHECK_MALLOC(tag, TAG_LEN, sock);


  unsigned int cont_sc = get_usr_cont_sc(usr_2);
  unsigned char* cont_sc_byte = NULL;
  CHECK_MALLOC(cont_sc_byte, sizeof(int), sock);
  int_to_byte(cont_sc, cont_sc_byte);


  // Create aad (msg_type || cont_client_server || nonce)
  free(aad);
  aad_len = 1 + sizeof(int) + sizeof(int);
  aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);


  unsigned char* type_byte = NULL;
  CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
  type_byte[0] = (unsigned char) MSG_TYPE_NONCE;


  memcpy(aad, type_byte, 1);
  memcpy(&aad[1], cont_sc_byte, sizeof(int));
  memcpy(&aad[1 + sizeof(int)], nonce_byte, sizeof(int));
  increase_usr_cont_sc(usr_2);


  // Encrypt the plaintext
  unsigned char* session_key_usr2 = get_usr_session_key(usr_2);
  if(session_key_usr2 == NULL){
    cout<<"\nError: invalid session key of user2 in read_and_forward_M_1_1"<<endl;
    return false;
  }


  ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key_usr2, iv, aad, aad_len, ct, TAG_LEN, tag);
  if(ct_len == -10){
    cout<<"\nError: invalid encryption in read_and_forward_M_1_1"<<endl;
    return false;
  }


  // Create the message to send
  int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + iv_len;
  int payload_len = msg_len - HEADER_LEN_SESSION;


  free(rcv_buff);
  rcv_buff = NULL;
  CHECK_MALLOC(rcv_buff, sizeof(int), sock);
  int_to_byte(payload_len, rcv_buff);


  free(ct_len_byte);
  ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
  int_to_byte(ct_len, ct_len_byte);


  free(aad_len_byte);
  aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  int_to_byte(aad_len, aad_len_byte);


  unsigned char* msg = NULL;
  CHECK_MALLOC(msg, msg_len, sock);
  memcpy(msg, rcv_buff, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, TAG_LEN);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], (unsigned char*) iv, iv_len);


  long dst_sock = get_usr_socket(usr_2);
  if(dst_sock == -1){
    cout<<"\nError: invalid dst_sock cont in read_and_forward_M_1_1"<<endl;
    return false;
  }


  ret = sendn(dst_sock, msg, msg_len);
  S_CHECK_ERROR_INT(ret, false);


  FREE5(pt, iv, ct, tag, cont_sc_byte);
  FREE4(rcv_buff, ct_len_byte, msg, type_byte);

  return true;


}


// Used by client
int read_M_1_2(long sock, unsigned char* session_key, unsigned int* cont_sc){

  int ret = 0;

  // Reading message header (payload_len)
  unsigned char* rcv_buff = NULL;
  CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
  ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
  C_CHECK_READ(ret, sock);
  int payload_dim = 0;
  memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


  // Read aad_len and aad
  unsigned char* aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  ret = readn(sock, aad_len_byte, sizeof(int));
  C_CHECK_READ(ret, sock);
  int aad_len = 0;
  memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);
  ret = readn(sock, aad, aad_len);
  C_CHECK_READ(ret, sock);


  // Read msg_type
  char msg_type = (char) aad[0];
  if(MSG_TYPE_NONCE != msg_type){
      cerr<<"Error: invalid message type in read_M_1_2"<<endl;
      return -1;
  }


  //Check the counter
  unsigned int rcv_cont = 0;
  memcpy(&rcv_cont, &aad[1], sizeof(int));
  if(rcv_cont != (*cont_sc)){
      cerr<<"Error: invalid cont in read_M_1_2"<<endl;
      return -1;
  }
  *cont_sc = *cont_sc + 1;


  // Read nonce
  unsigned char* nonce_byte = NULL;
  CHECK_MALLOC(nonce_byte, sizeof(int), sock);
  memcpy(nonce_byte, &aad[1 + sizeof(int)], sizeof(int));
  int nonce = -1;
  memcpy(&nonce, nonce_byte, sizeof(int)); // Conversion of nonce from byte to int


  // Read ct_len and ct
  unsigned char* ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
  ret = readn(sock, ct_len_byte, sizeof(int));
  C_CHECK_READ(ret, sock);
  int ct_len = 0;
  memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

  unsigned char* ct = NULL;
  CHECK_MALLOC(ct, ct_len, sock);
  ret = readn(sock, ct, ct_len);
  C_CHECK_READ(ret, sock);


  // Read tag
  unsigned char* tag = NULL;
  CHECK_MALLOC(tag, TAG_LEN, sock);
  ret = readn(sock, tag, TAG_LEN);
  C_CHECK_READ(ret, sock);


  // Read iv
  int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
  unsigned char* iv = NULL;
  CHECK_MALLOC(iv, iv_len, sock);
  ret = readn(sock, iv, iv_len);
  C_CHECK_READ(ret, sock);


  // Decrypt the ciphertext
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, ct_len, sock);
  int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
  if(result == -10 || result == -1){
    cerr<<"\nError: invalid decryption in read_M_1_2, (error result: "<<result<<")"<<endl;
    return -1;
  }


  FREE5(rcv_buff, ct_len_byte, ct, tag, iv);
  free(pt);


  return nonce;

}


// Used by client
bool send_M_2_1(long sock, unsigned char* session_key, unsigned int* cont_cs, EVP_PKEY* eph_pubkey, string usrname, int nonce){

  int ret = 0;

  // Encrypt the plaintext
  int pt_len = 1;
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, pt_len, sock);
  pt[0] = DUMMY_BYTE;


  int iv_len = IV_LEN;
  unsigned char* iv = generate_random_bytes(iv_len);
  if(iv == NULL){
    cout<<"\nError: invalid iv in send_M_2_1"<<endl;
    return false;
  }


  int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
  unsigned char* ct = NULL;
  CHECK_MALLOC(ct, ct_len, sock);


  int tag_len = TAG_LEN;
  unsigned char* tag = NULL;
  CHECK_MALLOC(tag, tag_len, sock);


  unsigned char* cont_byte = NULL;
  CHECK_MALLOC(cont_byte, sizeof(int), sock);
  int_to_byte((*cont_cs), cont_byte);
  *cont_cs = *cont_cs + 1;


  int eph_pubkey_len = 0;
  unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);
  if(eph_pubkey_byte == NULL){
    cout<<"\nError: invalid eph_pubkey_byte in send_M_2_1"<<endl;
    return false;
  }
  unsigned char* eph_pubkey_len_byte = NULL;
  CHECK_MALLOC(eph_pubkey_len_byte, sizeof(int), sock);
  int_to_byte(eph_pubkey_len, eph_pubkey_len_byte);


  unsigned char* nonce_byte = NULL;
  CHECK_MALLOC(nonce_byte, sizeof(int), sock);
  int_to_byte(nonce, nonce_byte);


  // Create the plaintext to sign ( nonce || eph_pubkey )
  int pt_to_sign_len = sizeof(int) + eph_pubkey_len;
  unsigned char* pt_to_sign = NULL;
  CHECK_MALLOC(pt_to_sign, pt_to_sign_len, sock);
  memcpy(pt_to_sign, nonce_byte, sizeof(int));
  memcpy(&pt_to_sign[sizeof(int)], eph_pubkey_byte, eph_pubkey_len);

  string private_key_path = "./../" + usrname + "_private_key.pem";
  EVP_PKEY* private_key = read_private_key(private_key_path);
  if(private_key == NULL){
    cout<<"\nError: invalid private_key in send_M_2_1"<<endl;
    return false;
  }

  int sign_len = EVP_PKEY_size(private_key);
  unsigned char* sign = NULL;
  CHECK_MALLOC(sign, sign_len, sock);

  sign_len = dig_sign_sgn(SIGNATURE_ALGORITHM, private_key, pt_to_sign, pt_to_sign_len, sign);
  if(sign_len == -10){
    cout<<"\nError: invalid signature generation in send_M_2_1"<<endl;
    return false;
  }


  // Create aad (msg_type || cont_client_server || dim_eph_pubkey || eph_pubkey || signature)
  int aad_len = 1 + sizeof(int) + sizeof(int) + eph_pubkey_len + sign_len;
  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);

  unsigned char* type_byte = NULL;
  CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
  type_byte[0] = (unsigned char) MSG_TYPE_EPH_PUBKEY;

  memcpy(aad, type_byte, 1);
  memcpy(&aad[1], cont_byte, sizeof(int));
  memcpy(&aad[1 + sizeof(int)], eph_pubkey_len_byte, sizeof(int));
  memcpy(&aad[1 + sizeof(int) + sizeof(int)], eph_pubkey_byte, eph_pubkey_len);
  memcpy(&aad[1 + sizeof(int) + sizeof(int) + eph_pubkey_len], sign, sign_len);


  // Encrypt the plaintext
  ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
  if(ct_len == -10){
    cout<<"\nError: invalid encryption in send_M_2_1"<<endl;
    return false;
  }


  // Create the message to send
  int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
  int payload_len = msg_len - HEADER_LEN_SESSION;

  unsigned char* payload_len_byte = NULL;
  CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
  int_to_byte(payload_len, payload_len_byte);

  unsigned char* ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
  int_to_byte(ct_len, ct_len_byte);

  unsigned char* aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  int_to_byte(aad_len, aad_len_byte);

  unsigned char* msg = NULL;
  CHECK_MALLOC(msg, msg_len, sock);
  memcpy(msg, payload_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);


  ret = sendn(sock, msg, msg_len);
  C_CHECK_ERROR_INT(ret, sock);


  FREE5(pt, iv, ct, tag, cont_byte);
  FREE4(payload_len_byte, ct_len_byte, msg, type_byte);
  EVP_PKEY_free(private_key);

  return true;


}


// Used by Server
bool read_and_forward_M_2_1(string usr_name, string usr_2){

    int ret = 0;


    long sock = get_usr_socket(usr_name);
    if(sock == -1){
      cout<<"\nError: invalid socket in read_and_forward_M_2_1"<<endl;
      return false;
    }


    unsigned char* session_key = get_usr_session_key(usr_name);
    if(session_key == NULL){
      cout<<"\nError: invalid session_key in read_and_forward_M_2_1"<<endl;
      return false;
    }


    unsigned int cont_cs = get_usr_cont_cs(usr_name);


    // Reading message header (payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    S_CHECK_ERROR_INT(ret, false);
    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


    // Read aad_len and aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    ret = readn(sock, aad_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, false);

    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    S_CHECK_ERROR_INT(ret, false);


    // Read ct_len and ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    ret = readn(sock, ct_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, false);
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);
    ret = readn(sock, ct, ct_len);
    S_CHECK_ERROR_INT(ret, false);


    // Read tag
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);
    ret = readn(sock, tag, TAG_LEN);
    S_CHECK_ERROR_INT(ret, false);


    // Read iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);
    ret = readn(sock, iv, iv_len);
    S_CHECK_ERROR_INT(ret, false);


    // Read msg_type
    char msg_type = (char) aad[0];
    if( MSG_TYPE_EPH_PUBKEY != msg_type){
        cerr<<"\nError: invalid message type in read_and_forward_M_2_1"<<endl;
        return false;
    }


    //Check the counter
    unsigned int rcv_cont = 0;
    memcpy(&rcv_cont, &aad[1], sizeof(int));
    if(rcv_cont != cont_cs){
        cerr<<"\nError: invalid cont in read_and_forward_M_2_1"<<endl;
        return false;
    }
    increase_usr_cont_cs(usr_name);


    // Decrypt the ciphertext
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, ct_len, sock);
    int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(result == -10 || result == -1){
      cerr<<"\nError: invalid decryption in read_and_forward_M_2_1, (error result: "<<result<<")"<<endl;
      return false;
    }


    //Read the message for client 2
    int msg_client_len = aad_len - 1 - sizeof(int);
    unsigned char* msg_client = NULL;
    CHECK_MALLOC(msg_client, msg_client_len, sock);
    memcpy(msg_client, &aad[1 + sizeof(int)], msg_client_len);


    // <><><><><><><><><><><><> Phase 2: forward from client 2 (usr_name) to client 1 (usr_2) <><><><><><><><><><><><>

    // Encrypt the plaintext
    int pt_len = 1;

    free(iv);
    iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError: invalid iv in read_and_forward_M_2_1."<<endl;
      return false;
    }


    free(ct);
    ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);


    free(tag);
    tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);


    unsigned int cont_sc = get_usr_cont_sc(usr_2);
    unsigned char* cont_sc_byte = NULL;
    CHECK_MALLOC(cont_sc_byte, sizeof(int), sock);
    int_to_byte(cont_sc, cont_sc_byte);


    // Create aad (msg_type || cont_client_server || eph_pubkey_len || eph_pubkey || sign)
    free(aad);
    aad_len = 1 + sizeof(int) + msg_client_len;
    aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);

    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_EPH_PUBKEY;
    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_sc_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int)], msg_client, msg_client_len);

    increase_usr_cont_sc(usr_2);


    // Encrypt the plaintext
    unsigned char* session_key_usr2 = get_usr_session_key(usr_2);
    if(session_key_usr2 == NULL){
      cout<<"\nError: invalid session_key_usr2 in read_and_forward_M_2_1."<<endl;
      return false;
    }

    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key_usr2, iv, aad, aad_len, ct, TAG_LEN, tag);
    if(ct_len == -10){
      cout<<"\nError: invalid decryption in read_and_forward_M_2_1."<<endl;
      return false;
    }


    // Create the message to send
    int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + iv_len;
    int payload_len = msg_len - HEADER_LEN_SESSION;

    free(rcv_buff);
    rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, sizeof(int), sock);
    int_to_byte(payload_len, rcv_buff);

    free(ct_len_byte);
    ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    int_to_byte(ct_len, ct_len_byte);

    free(aad_len_byte);
    aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg = NULL;
    CHECK_MALLOC(msg, msg_len, sock);
    memcpy(msg, rcv_buff, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, TAG_LEN);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], (unsigned char*) iv, iv_len);


    long dst_sock = get_usr_socket(usr_2);
    if(dst_sock == -1){
      cout<<"\nError: invalid dst_sock in read_and_forward_M_2_1."<<endl;
      return false;
    }


    ret = sendn(dst_sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);


    FREE5(pt, iv, ct, tag, cont_sc_byte);
    FREE5(rcv_buff, ct_len_byte, msg, type_byte, msg_client);

    return true;

}


// Used by client
unsigned char* read_M_2_2(long sock, unsigned char* session_key, unsigned int* cont, int* eph_pubkey_len, int nonce, unsigned char* usr2_pubkey, int usr2_pubkey_len){

    int ret = 0;

    // Reading message header (payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    C_CHECK_READ(ret, sock);

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


    // Read aad_len and aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    ret = readn(sock, aad_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);

    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    C_CHECK_READ(ret, sock);


    // Read ct_len and ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    ret = readn(sock, ct_len_byte, sizeof(int));
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);
    ret = readn(sock, ct, ct_len);
    C_CHECK_READ(ret, sock);


    // Read tag
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);
    ret = readn(sock, tag, TAG_LEN);
    C_CHECK_READ(ret, sock);


    // Read iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);
    ret = readn(sock, iv, iv_len);
    C_CHECK_READ(ret, sock);


    // Read msg_type
    char msg_type = (char) aad[0];
    if(MSG_TYPE_EPH_PUBKEY != msg_type){
        cout<<"\nError: invalid message type in read_M_2_2"<<endl;
        return NULL;
    }


    //Check the counter
    unsigned int rcv_cont = 0;
    memcpy(&rcv_cont, &aad[1], sizeof(int));
    if(rcv_cont != (*cont)){
        cerr<<"Error: invalid cont in read_M_2_2"<<endl;
        return NULL;
    }
    *cont = *cont + 1;


    // Decrypt the ciphertext
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, ct_len, sock);
    int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(result == -10 || result == -1){
      cerr<<"Error: invalid decryption in read_M_2_2, (error result: "<<result<<")"<<endl;
      return NULL;
    }


    // Read eph public key
    unsigned char* eph_pubkey_len_byte = NULL;
    CHECK_MALLOC(eph_pubkey_len_byte, sizeof(int), sock);
    memcpy(eph_pubkey_len_byte, &aad[1 + sizeof(int)], sizeof(int));
    memcpy(eph_pubkey_len, eph_pubkey_len_byte, sizeof(int)); // Conversion from byte to int

    unsigned char* eph_pubkey = NULL;
    CHECK_MALLOC(eph_pubkey, (*eph_pubkey_len), sock);
    memcpy(eph_pubkey, &aad[1 + sizeof(int) + sizeof(int)], (*eph_pubkey_len));


    // Read the signature ( nonce || eph_pubkey )
    int sign_len = aad_len - 1 - sizeof(int)*2 - (*eph_pubkey_len);
    unsigned char* sign = NULL;
    CHECK_MALLOC(sign, sign_len, sock);
    memcpy(sign, &aad[1 + sizeof(int) + sizeof(int) + (*eph_pubkey_len)], sign_len);


    // Create the buffer to verify signature
    int pt_sign_len = sizeof(int) + (*eph_pubkey_len);
    unsigned char* pt_sign = NULL;
    CHECK_MALLOC(pt_sign, pt_sign_len, sock);

    unsigned char* nonce_byte = NULL;
    CHECK_MALLOC(nonce_byte, sizeof(int), sock);
    int_to_byte(nonce, nonce_byte);

    memcpy(pt_sign, nonce_byte, sizeof(int));
    memcpy(&pt_sign[sizeof(int)], eph_pubkey, (*eph_pubkey_len));

    EVP_PKEY* usr2_PKEY = get_public_key_to_PKEY(usr2_pubkey, usr2_pubkey_len);
    if(usr2_PKEY == NULL){
      cout<<"\nError: user2 public key is null in read_M_2_2."<<endl;
      return NULL;
    }

    int r = dig_sign_verif(SIGNATURE_ALGORITHM, usr2_PKEY, sign, sign_len, pt_sign, pt_sign_len);
    if(r == 0){
      cout<<"\nError: invalid signature in read_M_2_2."<<endl;
      return NULL;
    }
    else{
      if(r == -1 || r == -10){
        cout<<"\nError: OpenSSL API error during signature verification in read_M_2_2."<<endl;
        return NULL;
      }
    }


    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);
    free(pt);


    return eph_pubkey;

}


// Used by client
bool send_M_3_1(long sock, string usrname, unsigned char* session_key, unsigned int* cont_cs, unsigned char* eph_pubkey, int eph_pubkey_len, unsigned char* session_client_key, int session_client_key_len){

    int ret = 0;

    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);
    pt[0] = DUMMY_BYTE;

    int iv_len = IV_LEN;
    unsigned char* iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError: invalid iv in send_M_3_1."<<endl;
      return false;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);

    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);

    unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
    int_to_byte((*cont_cs), cont_byte);
    *cont_cs = *cont_cs + 1;

    //Encrypt session_client_key with eph public key
    unsigned char* pt_envelope = session_client_key;
    int pt_envelope_len = session_client_key_len;

    EVP_PKEY* eph_PKEY = get_public_key_to_PKEY(eph_pubkey, eph_pubkey_len);
    if(eph_PKEY == NULL){
      cout<<"\nError: invalid ephemeral public key in send_M_3_1."<<endl;
      return false;
    }

    int encrypted_symkey_len = EVP_PKEY_size(eph_PKEY);
    unsigned char* encrypted_symkey = NULL;
    CHECK_MALLOC(encrypted_symkey, encrypted_symkey_len, sock);

    int iv_envelope_len = IV_LEN_ENVELOPE;
    unsigned char* iv_envelope = generate_random_bytes(iv_envelope_len);
    if(iv_envelope == NULL){
      cout<<"\nError: invalid iv of digital envelope in send_M_3_1."<<endl;
      return false;
    }

    int ct_envelope_len = pt_envelope_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_EXCHANGE_K_SESS);
    unsigned char* ct_envelope = NULL;
    CHECK_MALLOC(ct_envelope, ct_envelope_len, sock);
    ct_envelope_len = dig_env_encr(SYMMETRIC_CIPHER_EXCHANGE_K_SESS, eph_PKEY, pt_envelope, pt_envelope_len, encrypted_symkey, encrypted_symkey_len, iv_envelope, ct_envelope);
    if(ct_envelope_len == -10){
      cout<<"\nError: invalid digital envelope encryption in send_M_3_1."<<endl;
      return false;
    }


    // Create the plaintext to sign ( {Ksess_c1c2}_eph_pubkey || eph_pubkey )
    int pt_to_sign_len = ct_envelope_len + eph_pubkey_len;
    unsigned char* pt_to_sign = NULL;
    CHECK_MALLOC(pt_to_sign, pt_to_sign_len, sock);
    memcpy(pt_to_sign, ct_envelope, ct_envelope_len);
    memcpy(&pt_to_sign[ct_envelope_len], eph_pubkey, eph_pubkey_len);

    string private_key_path = "./../" + usrname + "_private_key.pem";
    EVP_PKEY* private_key = read_private_key(private_key_path);
    if(private_key == NULL){
      cout<<"\nError: invalid private key in send_M_3_1."<<endl;
      return false;
    }

    int sign_len = EVP_PKEY_size(private_key);
    unsigned char* sign = NULL;
    CHECK_MALLOC(sign, sign_len, sock);

    sign_len = dig_sign_sgn(SIGNATURE_ALGORITHM, private_key, pt_to_sign, pt_to_sign_len, sign);
    if(sign_len == -10){
      cout<<"\nError: invalid signature generation in send_M_3_1."<<endl;
      return false;
    }

    unsigned char* sign_len_byte = NULL;
    CHECK_MALLOC(sign_len_byte, sizeof(int), sock);
    int_to_byte(sign_len, sign_len_byte);

    unsigned char* ct_envelope_len_byte = NULL;
    CHECK_MALLOC(ct_envelope_len_byte, sizeof(int), sock);
    int_to_byte(ct_envelope_len, ct_envelope_len_byte);

    unsigned char* encrypted_symkey_len_byte = NULL;
    CHECK_MALLOC(encrypted_symkey_len_byte, sizeof(int), sock);
    int_to_byte(encrypted_symkey_len, encrypted_symkey_len_byte);


    // Create aad (msg_type || cont_client_server || sign_len || sign || ct_len || ct || encr_sym_key_len || encr_sym_key || iv)
    int aad_len = 1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_envelope_len + sizeof(int) + encrypted_symkey_len + iv_envelope_len;
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);

    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_SESSION_KEY;

    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int)], sign_len_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int) + sizeof(int)], sign, sign_len);
    memcpy(&aad[1 + sizeof(int) + sizeof(int) + sign_len], ct_envelope_len_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int)], ct_envelope, ct_envelope_len);
    memcpy(&aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_envelope_len], encrypted_symkey_len_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_envelope_len + sizeof(int)], encrypted_symkey, encrypted_symkey_len);
    memcpy(&aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_envelope_len + sizeof(int) + encrypted_symkey_len], iv_envelope, iv_envelope_len);


    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError: invalid encryption in send_M_3_1."<<endl;
      return false;
    }


    // Create the message to send
    int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_LEN_SESSION;

    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg = NULL;
    CHECK_MALLOC(msg, msg_len, sock);

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);


    ret = sendn(sock, msg, msg_len);
    C_CHECK_ERROR_INT(ret, sock);


    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);

    return true;

}


// Used by server
bool read_and_forward_M_3_1(string usr_name, string usr_2){

    int ret = 0;


    long sock = get_usr_socket(usr_name);
    if(sock == -1){
        cout<<"\nError: invalid socket in read_and_forward_M_3_1."<<endl;
        return false;
    }


    unsigned char* session_key = get_usr_session_key(usr_name);
    if(session_key == NULL){
        cout<<"\nError: invalid session key in read_and_forward_M_3_1."<<endl;
        return false;
    }


    unsigned int cont_cs = get_usr_cont_cs(usr_name);


    // Reading message header (payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    S_CHECK_ERROR_INT(ret, false);
    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


    // Read aad_len and aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    ret = readn(sock, aad_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, false);
    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    S_CHECK_ERROR_INT(ret, false);


    // Read ct_len and ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    ret = readn(sock, ct_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, false);
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);
    ret = readn(sock, ct, ct_len);
    S_CHECK_ERROR_INT(ret, false);


    // Read tag
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);
    ret = readn(sock, tag, TAG_LEN);
    S_CHECK_ERROR_INT(ret, false);


    // Read iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);
    ret = readn(sock, iv, iv_len);
    S_CHECK_ERROR_INT(ret, false);


    // Read msg_type
    char msg_type = (char) aad[0];
    if(MSG_TYPE_SESSION_KEY != msg_type){
        cerr<<"Error: invalid message type in read_and_forward_M_3_1"<<endl;
        return false;
    }


    //Check the counter
    unsigned int rcv_cont = 0;
    memcpy(&rcv_cont, &aad[1], sizeof(int));
    if(rcv_cont != cont_cs){
        cerr<<"Error: invalid cont in read_and_forward_M_3_1"<<endl;
        return false;
    }
    increase_usr_cont_cs(usr_name);


    // Decrypt the ciphertext
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, ct_len, sock);
    int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(result == -10 || result == -1){
      cerr<<"Error: invalid decryption in read_and_forward_M_3_1, (error result: "<<result<<")"<<endl;
      return false;
    }


    //Read the message for client 2
    int msg_client_len = aad_len - 1 - sizeof(int);
    unsigned char* msg_client = NULL;
    CHECK_MALLOC(msg_client, msg_client_len, sock);
    memcpy(msg_client, &aad[1 + sizeof(int)], msg_client_len);


    // <><><><><><><><><><><><> Phase 2: forward from client 2 (usr_name) to client 1 (usr_2) <><><><><><><><><><><><>


    // Encrypt the plaintext
    int pt_len = 1;

    free(iv);
    iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError: invalid iv in read_and_forward_M_3_1."<<endl;
      return false;
    }


    free(ct);
    ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);


    free(tag);
    tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);


    unsigned int cont_sc = get_usr_cont_sc(usr_2);
    unsigned char* cont_sc_byte = NULL;
    CHECK_MALLOC(cont_sc_byte, sizeof(int), sock);
    int_to_byte(cont_sc, cont_sc_byte);


    // Create aad (msg_type || cont_client_server || sign_len || sign || ct_len || ct || encr_sym_key_len || encr_sym_key || iv)
    free(aad);
    aad_len = 1 + sizeof(int) + msg_client_len;
    aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);

    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_SESSION_KEY;

    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_sc_byte, sizeof(int));
    memcpy(&aad[1 + sizeof(int)], msg_client, msg_client_len);
    increase_usr_cont_sc(usr_2);


    // Encrypt the plaintext
    unsigned char* session_key_usr2 = get_usr_session_key(usr_2);
    if(session_key_usr2 == NULL){
      cout<<"\nError: invalid session_key_usr2 in read_and_forward_M_3_1."<<endl;
      return false;
    }

    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key_usr2, iv, aad, aad_len, ct, TAG_LEN, tag);
    if(ct_len == -10){
      cout<<"\nError: invalid encryption in read_and_forward_M_3_1."<<endl;
      return false;
    }


    // Create the message to send
    int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN + iv_len;
    int payload_len = msg_len - HEADER_LEN_SESSION;

    free(rcv_buff); //payload len
    rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, sizeof(int), sock);
    int_to_byte(payload_len, rcv_buff);

    free(ct_len_byte);
    ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    int_to_byte(ct_len, ct_len_byte);

    free(aad_len_byte);
    aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg = NULL;
    CHECK_MALLOC(msg, msg_len, sock);
    memcpy(msg, rcv_buff, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, TAG_LEN);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], (unsigned char*) iv, iv_len);


    long dst_sock = get_usr_socket(usr_2);
    if(dst_sock == -1){
      cout<<"\nError: invalid dst_sock in read_and_forward_M_3_1."<<endl;
      return false;
    }


    ret = sendn(dst_sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);


    FREE5(pt, iv, ct, tag, cont_sc_byte);
    FREE4(rcv_buff, ct_len_byte, msg, type_byte);

    return true;

}


// Used by client
unsigned char* read_M_3_2(long sock, string usrname, unsigned char* session_key, unsigned int* cont, unsigned char* eph_pk, int eph_pb_len, EVP_PKEY* eph_privkey, unsigned char* usr2_pubkey, int usr2_pubkey_len, int* pt_client_len){

  int ret = 0;

  // Reading message header (payload_len)
  unsigned char* rcv_buff = NULL;
  CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
  ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
  C_CHECK_READ(ret, sock);
  int payload_dim = 0;
  memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


  // Read aad_len and aad
  unsigned char* aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  ret = readn(sock, aad_len_byte, sizeof(int));
  C_CHECK_READ(ret, sock);
  int aad_len = 0;
  memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);
  ret = readn(sock, aad, aad_len);
  C_CHECK_READ(ret, sock);


  // Read ct_len and ct
  unsigned char* ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
  ret = readn(sock, ct_len_byte, sizeof(int));
  C_CHECK_READ(ret, sock);
  int ct_len = 0;
  memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

  unsigned char* ct = NULL;
  CHECK_MALLOC(ct, ct_len, sock);
  ret = readn(sock, ct, ct_len);
  C_CHECK_READ(ret, sock);


  // Read tag
  unsigned char* tag = NULL;
  CHECK_MALLOC(tag, TAG_LEN, sock);
  ret = readn(sock, tag, TAG_LEN);
  C_CHECK_READ(ret, sock);


  // Read iv
  int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
  unsigned char* iv = NULL;
  CHECK_MALLOC(iv, iv_len, sock);
  ret = readn(sock, iv, iv_len);
  C_CHECK_READ(ret, sock);


  // Read msg_type
  char msg_type = (char) aad[0];
  if(MSG_TYPE_SESSION_KEY != msg_type){
      cerr<<"Error: invalid message type in read_M_3_2"<<endl;
      return NULL;
  }


  //Check the counter
  unsigned int rcv_cont = 0;
  memcpy(&rcv_cont, &aad[1], sizeof(int));
  if(rcv_cont != (*cont)){
      cerr<<"Error: invalid cont in read_M_3_2."<<endl;
      return NULL;
  }
  *cont = *cont + 1;


  // Decrypt the ciphertext
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, ct_len, sock);
  int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
  if(result == -10 || result == -1){
    cout<<"\nError: invalid decryption in read_M_3_2, (error result: "<<result<<")"<<endl;
    return NULL;
  }


  // Read the signature ({Ksess_c1c2}_eph_pub_key || eph_pub_key)
  unsigned char* sign_len_byte = NULL;
  CHECK_MALLOC(sign_len_byte, sizeof(int), sock);
  memcpy(sign_len_byte, &aad[1 + sizeof(int)], sizeof(int));
  int sign_len = -1;
  memcpy(&sign_len, sign_len_byte, sizeof(int)); // Conversion from byte to int

  unsigned char* sign = NULL;
  CHECK_MALLOC(sign, sign_len, sock);
  memcpy(sign, &aad[1 + sizeof(int) + sizeof(int)], sign_len);


  // Read the ct
  unsigned char* ct_client_len_byte = NULL;
  CHECK_MALLOC(ct_client_len_byte, sizeof(int), sock);
  memcpy(ct_client_len_byte, &aad[1 + sizeof(int) + sizeof(int) + sign_len], sizeof(int));
  int ct_client_len = -1;
  memcpy(&ct_client_len, ct_client_len_byte, sizeof(int)); // Conversion from byte to int

  unsigned char* ct_client = NULL;
  CHECK_MALLOC(ct_client, ct_client_len, sock);
  memcpy(ct_client, &aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int)], ct_client_len);


  // Create a buffer for signature verification
  EVP_PKEY* usr2_PKEY = get_public_key_to_PKEY(usr2_pubkey, usr2_pubkey_len);
  if(usr2_PKEY == NULL){
    cout<<"\nError: invalid usr2_pubkey in read_M_3_2"<<endl;
    return NULL;
  }

  int pt_to_verify_len = ct_client_len + eph_pb_len;
  unsigned char* pt_to_verify = NULL;
  CHECK_MALLOC(pt_to_verify, pt_to_verify_len, sock);
  memcpy(pt_to_verify, ct_client, ct_client_len);
  memcpy(&pt_to_verify[ct_client_len], eph_pk, eph_pb_len);

  int r = dig_sign_verif(SIGNATURE_ALGORITHM, usr2_PKEY, sign, sign_len, pt_to_verify, pt_to_verify_len);
  if(r == 0){
    cout<<"\nError: invalid signature in read_M_3_2"<<endl;
    return NULL;
  }
  else{
    if(r == -1 || r == -10){
      cout<<"\nError: some error during verification of signature in read_M_3_2."<<endl;
      return NULL;
    }
  }


  // Read the encrypted sym key len (for digital envelope)
  unsigned char* encr_sym_key_len_byte = NULL;
  CHECK_MALLOC(encr_sym_key_len_byte, sizeof(int), sock);
  memcpy(encr_sym_key_len_byte, &aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_client_len], sizeof(int));
  int encr_sym_key_len = -1;
  memcpy(&encr_sym_key_len, encr_sym_key_len_byte, sizeof(int)); // Conversion from byte to int

  unsigned char* encr_sym_key = NULL;
  CHECK_MALLOC(encr_sym_key, encr_sym_key_len, sock);
  memcpy(encr_sym_key, &aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_client_len + sizeof(int)], encr_sym_key_len);

  // Read the iv of digital envelope
  unsigned char* iv_envelope = NULL;
  CHECK_MALLOC(iv_envelope, IV_LEN_ENVELOPE, sock);
  memcpy(iv_envelope, &aad[1 + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + ct_client_len + sizeof(int) + encr_sym_key_len], IV_LEN_ENVELOPE);

  unsigned char* pt_client = NULL;
  CHECK_MALLOC(pt_client, ct_client_len, sock);

  *pt_client_len = dig_env_decr(SYMMETRIC_CIPHER_EXCHANGE_K_SESS, eph_privkey, ct_client, ct_client_len, encr_sym_key, encr_sym_key_len, iv_envelope, pt_client);
  if((*pt_client_len) == -10){
    cout<<"\nError: invalid digital envelope decryption in read_M_3_2."<<endl;
    return NULL;
  }


  return pt_client;

}
