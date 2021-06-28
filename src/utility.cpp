#include "utility.h"
#include <signal.h>
#include <csignal>


pthread_t client_thread_reading;
pthread_t client_thread_sending;



// Struct that represents arguments that should be passed to thread client_thread_reading and client_thread_sending
typedef struct arguments{
    long ssock;                         //socket with server
    unsigned char* session_key;         //session key between server and user
    unsigned char* session_key_client;  //session key between usr1 and usr2
    unsigned int* cont;                 //counter for message from server to client or for message from client to server (we use the address beacuse it should be modified from thread)
    unsigned int* logout_cont;          //counter needed to send logout message client and its thread (we use this only in that situation)
} my_args;



void signal_handler(int signum) {

  fflush(stdout);
  pthread_exit((void*) 1);

}


int readn(long fd, void *buf, size_t size) {

    size_t left = size;
    int r = 0;
    int letto_tmp = 0;
    char *bufptr = (char*)buf;

    while(left > 0) {
        if ((r = read(fd ,bufptr,left)) == -1) {
            if (errno == EINTR){
                continue;
            }
            else{
                if(errno == EAGAIN || errno == EWOULDBLOCK){ // to handle timeout on the socket
                    return -2;
                }
                  return -1; // generic error
            }
        }
        if (r == 0){ return 0; }   // handling socket close

        left    -= r;
        bufptr  += r;
        letto_tmp = letto_tmp + r;
    }

    return letto_tmp;
}



int sendn(long fd, void *buf, size_t size) {

    size_t left = size;
    int r;
    int letto_tmp = 0;
    char *bufptr = (char*)buf;

    while(left > 0) {
        if ((r = send(fd, bufptr, left, 0)) == -1 ) {
            if (errno == EINTR) continue;
            return -1;
        }

        if (r == 0) return 0;

        left    -= r;
        bufptr  += r;
        letto_tmp = letto_tmp + r;
    }

    return letto_tmp;
}



void set_socket_timeout(long sock, int timer){

    struct timeval tv;
    tv.tv_sec = timer;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

}



bool send_timeout_expired(long sock, unsigned char* session_key, unsigned int* cont){

    int ret = 0;

    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = generate_random_bytes(iv_len);

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

    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_TIMEOUT_EXPIRED;

    // Create aad ( msg_type || cont_client_server )
    int aad_len = 1 + sizeof(int);
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));


    pt[0] = DUMMY_BYTE;


    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in send_timeout_expired because of sym_auth_encr"<<endl;
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
    FREE5(payload_len_byte, ct_len_byte, msg, type_byte, aad);
    free(aad_len_byte);

    return true;

}



EVP_PKEY* read_pub_key(string file_name){

    FILE* fd_pub_key = fopen(file_name.c_str(), "r");
    if(fd_pub_key == NULL){
      return NULL;
    }

    EVP_PKEY* public_key = PEM_read_PUBKEY(fd_pub_key, NULL, NULL, NULL);
    if(public_key == NULL){
      return NULL;
    }

    fclose(fd_pub_key);

    return public_key;

}



EVP_PKEY* read_private_key(string file_name){

    FILE* fd_priv_key = fopen(file_name.c_str(), "r");
    C_CHECK_ERROR(fd_priv_key, -1);

    EVP_PKEY* private_key = PEM_read_PrivateKey(fd_priv_key, NULL, NULL, NULL);
    C_CHECK_ERROR(private_key, -1);

    fclose(fd_priv_key);

    return private_key;
}



void int_to_byte(int i, unsigned char* c){

  c[0] =  i & 0xFF;
  c[1] = (i>>8) & 0xFF;
  c[2] = (i>>16) & 0xFF;
  c[3] = (i>>24) & 0xFF;

}



void unsigned_int_to_byte(unsigned int i, unsigned char* c){

  c[0] =  i & 0xFF;
  c[1] = (i>>8) & 0xFF;
  c[2] = (i>>16) & 0xFF;
  c[3] = (i>>24) & 0xFF;

}



unsigned char* read_certificate(string cert_file_path, int* buff_cert_size){

    // Reading certificate from file
    FILE* f_cert = fopen(cert_file_path.c_str(), "r");
    if(!f_cert){ return NULL; }

    X509* server_cert = PEM_read_X509(f_cert, NULL, NULL, NULL);
    if(!server_cert){ return NULL; }
    fclose(f_cert);


    // Memory bio that has inside a memory buffer structured as a queue of bytes
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, server_cert); // Write server_cert into bio


    // Serialize the certificate
    unsigned char* buff_cert = NULL;
    *buff_cert_size = BIO_get_mem_data(bio, &buff_cert);
    if((*buff_cert_size) < 0){
        return NULL;
    }

    return buff_cert;

}



X509* deserialize_cert(unsigned char* cert_buff, int cert_size){

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, cert_buff, cert_size);

    X509* server_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);
    return server_cert;

}



void print_Server_cert_info(X509* server_cert){

    char* tmp = X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(server_cert), NULL, 0);
    cout << "\nCertificate of \n\t" << tmp << "\n\t(released by " << tmp2 << ") \n\tVERIFIED SUCCESSFULLY\n\n";

    free(tmp);
    free(tmp2);

}



EVP_PKEY* get_public_key_to_PKEY(unsigned char* public_key, int len){

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, public_key, len);

    EVP_PKEY* pk = NULL;
    pk =  PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return pk;

}



EVP_PKEY* get_private_key_to_PKEY(unsigned char* priv_key, int len){

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, priv_key, len);

    EVP_PKEY* pk =  PEM_read_bio_PrivateKey(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return pk;

}



unsigned char* get_public_key_to_byte(EVP_PKEY *public_key, int* pub_key_len){

    BIO *bio = NULL;
    unsigned char *key = NULL;
    int key_len = 0;

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, public_key);

    key_len = BIO_pending(bio);
    *pub_key_len = key_len;

    key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);

    BIO_read(bio, key, key_len);
    BIO_free_all(bio);

    return key;

}



unsigned char* read_usr_list(long sock, unsigned char* session_key, unsigned int* cont){

    int ret = 0;

    // Reading message header (payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    C_CHECK_READ(ret, sock);

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting byte to int


    // Reading aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    ret = readn(sock, aad_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);

    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting byte to int


    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    C_CHECK_READ(ret, sock);


    // Read ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    ret = readn(sock, ct_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);

    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting byte to int

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
    if( MSG_TYPE_USRS_LIST != msg_type ){
        cout<<"Error: invalid message type in read_usr_list."<<endl;
        return NULL;
    }

    //Convert cont from byte to int
    memcpy(cont, &aad[1], sizeof(int));
    *cont = *cont + 1;

    // Decrypt the ciphertext
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, (ct_len+1), sock);
    memset(pt, '\0', ct_len + 1);
    bool result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(result == false){
      cout<<"\nError: tag mismatch in read_usr_list"<<endl;
      return NULL;
    }


    cout<<"\n[------ ONLINE USERS ------]\n\n"<<pt<<endl;
    cout<<"[--------------------------]"<<endl;

    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);
    FREE2(aad, aad_len_byte);

    return pt;

}



string select_user_to_talk(string usr_online_list){

    string usr_to_talk = "";

    cout<<"\nSelect a user to talk with:"<<endl;

    bool good = false;
    while(!good){
        cin>>usr_to_talk;
        if(usr_online_list.find(usr_to_talk) == string::npos){
            cout<<"\nUsername "<<usr_to_talk<<" not in the list!"<<endl;
            good = false;
            return "ERR";
        }
        else{
            good = true;
        }
    }

    return usr_to_talk;
}



bool send_user_choice(long sock, unsigned char* session_key, unsigned int* cont, string usr_to_talk){

    int ret = 0;

    // Create the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);
    pt[0] = DUMMY_BYTE;

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = generate_random_bytes(iv_len);

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);

    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, tag_len, sock);

    // Create aad (msg_type || cont_client_server || usrname)
    int aad_len = -1;
    unsigned char* aad = NULL;

    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);

    unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
    int_to_byte((*cont), cont_byte);

    if(strlen(usr_to_talk.c_str()) == 0){
      aad_len = 1 + sizeof(int);
      CHECK_MALLOC(aad, aad_len, sock);

      type_byte[0] = (unsigned char) MSG_TYPE_CLIENT_WAIT;
    }
    else{
      if(strcmp(usr_to_talk.c_str(), "LOGOUT") != 0 ){

        aad_len = 1 + sizeof(int) + strlen(usr_to_talk.c_str());
        CHECK_MALLOC(aad, aad_len, sock);

        type_byte[0] = (unsigned char) MSG_TYPE_REQUEST_TO_TALK;

        copy(usr_to_talk.begin(), usr_to_talk.end(), &aad[1 + sizeof(int)]);

      }
      else{

        aad_len = 1 + sizeof(int);
        CHECK_MALLOC(aad, aad_len, sock);

        type_byte[0] = (unsigned char) MSG_TYPE_LOGOUT;

      }
    }

    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));


    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in symt_auth_encr in send_user_choice"<<endl;
      return false;
    }

    // Create the message to send
    int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_LEN_SESSION;

    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    int_to_byte(ct_len, ct_len_byte);

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

    *cont = *cont + 1;

    FREE5(pt, iv, ct, tag, cont_byte);
    FREE5(aad, payload_len_byte, ct_len_byte, msg, type_byte);
    free(aad_len_byte);

    return true;

}



string read_incoming_request(long sock, unsigned char* session_key, unsigned int* cont){

    int ret = 0;

    // Reading message header (payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    if(ret == -1 || ret == 0){
      cerr<<strerror(errno);
      ERR_print_errors_fp(stderr);
      close(sock);
      cout<<"\nCritical error: terminating client in read_incoming_request."<<endl;
      exit(1);
    }

    if(ret == -2){ //Timeout exprired
        return "TIMEOUT_EXPIRED";
    }

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting byte to int


    // Read aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);

    ret = readn(sock, aad_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);
    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting byte to int

    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    C_CHECK_READ(ret, sock);

    // Read msg_type
    char msg_type = (char) aad[0];
    if( MSG_TYPE_FORWARD_REQUEST_TO_TALK != msg_type){
        cerr<<"\nError: invalid message type in read_incoming_request"<<endl;
        return "ERR";
    }


    //Check on counter (before the decrypt and before the check of tag [authenticity])
    int cont_sc = 0;
    memcpy(&cont_sc, &aad[1], sizeof(int));

    if( cont_sc != (*cont) ){
        cerr<<"Error: invalid cont in read_incoming_request"<< endl;
        return "ERR";
    }

    *cont = *cont + 1;


    // Read ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);

    ret = readn(sock, ct_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting byte to int

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
    CHECK_MALLOC(pt, (ct_len + 1), sock);
    memset(pt, '\0', ct_len + 1);

    bool b_ret = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(b_ret == false){
      cout<<"\nError on sym_auth_decr in read_incoming_request"<<endl;
      return "ERR";
    }

    // Read the usr name that sent this request_to_talk
    string src_usr = (char*) pt;

    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);
    free(pt);

    return src_usr;

}



bool send_request_response(long sock, unsigned char* k_sess, unsigned int* cont, string usr_of_request, bool response){

    int ret = 0;

    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = generate_random_bytes(iv_len);

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

    unsigned char* type_byte = NULL; //(unsigned char*) malloc(sizeof(unsigned char));
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    if(response){
      type_byte[0] = (unsigned char) MSG_TYPE_REQUEST_ACCEPTED;
    }
    else{
      type_byte[0] = (unsigned char) MSG_TYPE_REQUEST_REFUSED;
    }

    // Create aad (msg_type || cont_client_server || usr_of_request)
    int aad_len = 1 + sizeof(int) + strlen(usr_of_request.c_str());
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));
    copy(usr_of_request.begin(), usr_of_request.end(), &aad[1 + sizeof(int)]);


    pt[0] = DUMMY_BYTE;


    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, k_sess, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in symt_auth_encr in send_request_response"<<endl;
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



int get_usr_input(){

    fd_set rfds;
    struct timeval tv;
    int retval;

    int action = -1;

    // Watch stdin (fd 0) to see when it has input.
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);

    // Wait up to five seconds.
    tv.tv_sec = TIMEOUT_RESPONSE;
    tv.tv_usec = 0;

    retval = select(1, &rfds, NULL, NULL, &tv);

    if (retval == -1){
      cout<<"\nError while getting input of client..."<<endl;
        return -2;
    }
    else if (retval){
        // FD_ISSET(0, &rfds) is true so input is available now.
        // Read data from stdin
        cin>>action;
        return action;
    }
    else{
        printf("Timeout expired.\n");
        return -1;
    }

}



unsigned char* read_request_response(long sock, unsigned int* cont, unsigned char* session_key, int* pubkey_len){

    int ret = 0;

    // Reading message header (payload_len)
    unsigned char* rcv_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_LEN_SESSION);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    C_CHECK_READ(ret, sock);

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int));

    // Read aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);

    ret = readn(sock, aad_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);
    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int));

    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    C_CHECK_READ(ret, sock);

    // Read ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);

    ret = readn(sock, ct_len_byte, sizeof(int));
    C_CHECK_READ(ret, sock);
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int));

    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);
    ret = readn(sock, ct, ct_len);
    C_CHECK_READ(ret, sock);


    // Read tag
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);
    ret = readn(sock, tag, TAG_LEN);
    C_CHECK_READ(ret, sock);


    // Read msg_type
    char msg_type = (char) aad[0];
    if( MSG_TYPE_FORWARD_REQUEST_ACCEPT != msg_type && MSG_TYPE_REQUEST_REFUSED != msg_type && MSG_TYPE_FORWARD_REQUEST_REFUSED != msg_type){
        cout<<"Error: invalid message type in read_request_response"<<endl;
        return NULL;
    }


    //Check the counter
    int rcv_cont = 0;
    memcpy(&rcv_cont, &aad[1], sizeof(int));

    if( rcv_cont != (*cont) ){
        cout<<"Error: invalid cont in read_request_response"<<endl;
        return NULL;
    }

    *cont = (*cont) + 1;


    // Read iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);
    ret = readn(sock, iv, iv_len);
    C_CHECK_READ(ret, sock);


    // Decrypt the ciphertext
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, ct_len, sock);
    bool b_ret = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(b_ret == false){
      cout<<"\nError on sym_auth_decr in read_request_response"<<endl;
      return NULL;
    }



    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);


    //if the response is the acceptance of the request, then in the message is already present the public key of other usr
    if(msg_type == MSG_TYPE_FORWARD_REQUEST_ACCEPT) {

        //Reading the public key from AAD
        int dim_k_pub_dst_usr = aad_len - sizeof(int) - 1;
        *pubkey_len = dim_k_pub_dst_usr;

        unsigned char* buff_k_pub_dst_usr = NULL;
        CHECK_MALLOC(buff_k_pub_dst_usr, dim_k_pub_dst_usr, sock)
        memcpy(buff_k_pub_dst_usr, &aad[1 + sizeof(int)], dim_k_pub_dst_usr);

        free(pt);

        return buff_k_pub_dst_usr;

    }
    else{ // Request refused for some reason

        free(pt);
        unsigned char* result_reject = NULL;
        CHECK_MALLOC(result_reject, 1, sock);
        result_reject[0] = 'R';
        return result_reject;
    }
}



unsigned char* read_incoming_pub_key(long sock, unsigned char* session_key, unsigned int* cont, int* usr2_pub_key_len){

    int ret = 0;

    // Reading message header (payload_len)
    unsigned char* rcv_buff = NULL;
    CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    C_CHECK_READ(ret, sock);

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


    // Read aad
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


    // Read ct
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


    //Check the counter
    unsigned int rcv_cont = 0;
    memcpy(&rcv_cont, aad, sizeof(int));

    if( rcv_cont != (*cont) ){
        cout<<"Error: invalid cont in read_incoming_pub_key"<<endl;
        return NULL;
    }

    *cont = *cont + 1;


    // Decrypt the ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    bool b_ret = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(b_ret == false){
      cout<<"\nError on sym_auth_decr read_incoming_pub_key"<<endl;
      return NULL;
    }


    // Read msg_type
    char msg_type = (char) pt[0];
    if( MSG_TYPE_EXCHANGE_USR_PUB_KEY != msg_type){
        cerr<<"Error: invalid message type in read_incoming_pub_key"<<endl;
        return NULL;
    }



    // Read public key
    int pubkey_len = aad_len - sizeof(int);

    unsigned char* public_key = NULL;
    CHECK_MALLOC(public_key, pubkey_len, sock);
    memcpy(public_key, &aad[sizeof(int)], pubkey_len);

    *usr2_pub_key_len = pubkey_len;


    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);
    free(pt);


    return public_key;

}



unsigned char* exchange_session_key_to_wait(long sock, string usrname, unsigned char* session_key, unsigned char* usr2_pub_key, int usr2_pubkey_len, unsigned int* cont_sc, unsigned int* cont_cs, int* K_sess_client_len){

  int ret = 0;

  //read M1.2
  int nonce = -1;
  nonce = read_M_1_2(sock, session_key, cont_sc);
  if(nonce == -1){
    cout<<"\nError while reading nonce in exchange_session_key_to_wait"<<endl;
    return NULL;
  }


  EVP_PKEY* eph_pubkey = NULL;
  EVP_PKEY* eph_privkey = NULL;
  generate_ephemeral_keys(&eph_privkey, &eph_pubkey);
  if(eph_pubkey == NULL || eph_privkey == NULL){
    cout<<"\nError while generating ephemeral keys in exchange_session_key_to_wait"<<endl;
    return NULL;
  }

  int eph_pub_key_len = -1;
  unsigned char* eph_pub_key = get_public_key_to_byte(eph_pubkey, &eph_pub_key_len); //ephemeral public key
  if(eph_pub_key == NULL){
    cout<<"\nError in exchange_session_key_to_wait because of get_public_key_to_byte"<<endl;
    return NULL;
  }


  ret = send_M_2_1(sock, session_key, cont_cs, eph_pubkey, usrname, nonce);
  if(ret == false){
    cout<<"\nError in get_public_key_to_byte because of send_M_2_1"<<endl;
    return NULL;
  }

  int session_key_clients_len = 0;
  unsigned char* session_client_key = NULL;
  session_client_key = read_M_3_2(sock, usrname, session_key, cont_sc, eph_pub_key, eph_pub_key_len, eph_privkey,
                                                  usr2_pub_key, usr2_pubkey_len, &session_key_clients_len);

  EVP_PKEY_free(eph_pubkey);
  EVP_PKEY_free(eph_privkey);
  memset(eph_pub_key, '\0', eph_pub_key_len);
  free(eph_pub_key);

  if(session_client_key == NULL){
    cout<<"\nError in get_public_key_to_byte because of read M_3_2"<<endl;
    return NULL;
  }

  *K_sess_client_len = session_key_clients_len;

  return session_client_key;
}



unsigned char* exchange_session_key_to_talk(long sock, string username, unsigned char* usr2_pub_key, int usr2_pub_key_len, unsigned int* cont_sc, unsigned int* cont_cs, unsigned char* session_key, int* session_key_client_len){

    int nonce = -1;
    nonce = send_M_1_1(sock, session_key, cont_cs); //M1.1 = send random nonce to other client
    if(nonce == -1){
      cout<<"\nError while reading nonce in exchange_session_key_to_talk because of send_M_1_1"<<endl;
      return NULL;
    }
    int eph_pubkey_len = -1;

    unsigned char* eph_pubkey = NULL;
    eph_pubkey = read_M_2_2(sock, session_key, cont_sc, &eph_pubkey_len, nonce, usr2_pub_key, usr2_pub_key_len); //M2.2 = read client ephemeral public key
    if(eph_pubkey == NULL){
      cout<<"\nError in exchange_session_key_to_talk because of read M_2_2"<<endl;
      return NULL;
    }

    int session_client_key_len_ = EVP_CIPHER_key_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* session_client_key = generate_random_bytes(session_client_key_len_);
    if(session_client_key == NULL ){
      cout<<"\nError in exchange_session_key_to_talk because of generate_random_bytes"<<endl;
      return NULL;
    }

    bool b_ret = send_M_3_1(sock, username, session_key, cont_cs, eph_pubkey, eph_pubkey_len, session_client_key, session_client_key_len_); //M3.1 = send session key encrypted with ephemeral public key
    memset(eph_pubkey, '\0', eph_pubkey_len);
    free(eph_pubkey);
    if(b_ret == false){
      cout<<"\nError in exchange_session_key_to_talk because of send_M_3_1"<<endl;
      return NULL;
    }

    *session_key_client_len = session_client_key_len_;

    return session_client_key;
}



bool read_session_message(long sock, unsigned char* session_key, unsigned char* session_key_client, unsigned int* cont_sc, unsigned int* cont_c2_c1){

  int ret = 0;

  // Reading message header (payload_len)
  unsigned char* rcv_buff = NULL;
  CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);

  ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
  C_CHECK_READ(ret, sock);

  int payload_dim = 0;
  memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


  // Read aad
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



  // Read ct
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
  if( MSG_TYPE_SESSION_MSG != msg_type){
      if(MSG_TYPE_LOGOUT == msg_type){
        cout<<"\nSession ended. Logging out."<<endl;
      }
      else{
        cout<<"Error: invalid message type in read_session_message"<<endl;
      }
      return false;
  }



  //Check the counter
  unsigned int rcv_cont = 0;
  memcpy(&rcv_cont, &aad[1], sizeof(int));

  if( rcv_cont != (*cont_sc) ){
      cerr<<"Error: invalid cont in read_session_message because of client nonce"<<endl;
      close(sock);
      return false;
  }

  *cont_sc = *cont_sc + 1;



  // Decrypt the ciphertext
  unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
  bool result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
  if(!result){
    cout<<"Error on authentication in read_session_message"<<endl;
    return false;
  }


  FREE3(rcv_buff, ct_len_byte, ct);
  FREE3(tag, iv, pt);


  // *******************************************************************

  //Reading the part of the message that client c2 sent to client c1, this part is inside aad between server and client

  // Read aad
  unsigned char* client_aad_len_byte = NULL;
  CHECK_MALLOC(client_aad_len_byte, sizeof(int), sock);
  memcpy(client_aad_len_byte, &aad[1 + sizeof(int)], sizeof(int));
  int client_aad_len = 0;
  memcpy(&client_aad_len, client_aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

  unsigned char* client_aad = NULL;
  CHECK_MALLOC(client_aad, client_aad_len, sock);
  memcpy(client_aad, &aad[1 + sizeof(int) + sizeof(int)], client_aad_len);


  // Read ct
  unsigned char* client_ct_len_byte = NULL;
  CHECK_MALLOC(client_ct_len_byte, sizeof(int), sock);
  memcpy(client_ct_len_byte, &aad[1 + sizeof(int) + sizeof(int) + client_aad_len], sizeof(int));
  int client_ct_len = 0;
  memcpy(&client_ct_len, client_ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

  unsigned char* client_ct = NULL;
  CHECK_MALLOC(client_ct, client_ct_len, sock);
  memcpy(client_ct, &aad[1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int)], client_ct_len);


  // Read tag
  unsigned char* client_tag = NULL;
  CHECK_MALLOC(client_tag, TAG_LEN, sock);
  memcpy(client_tag, &aad[1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int) + client_ct_len], TAG_LEN);



  // Read iv
  iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
  unsigned char* client_iv = NULL;
  CHECK_MALLOC(client_iv, iv_len, sock);
  memcpy(client_iv, &aad[1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int) + client_ct_len + TAG_LEN], iv_len);



  //Check the counter between c2 and c1
  unsigned int rcv_client_cont = 0;
  memcpy(&rcv_client_cont, client_aad, sizeof(int));

  if( rcv_client_cont != (*cont_c2_c1) ){
      cerr<<"Error: invalid cont_c2_c1 in read_session_message ---> cont from c2 to c1"<<endl;
      return false;
  }

  *cont_c2_c1 = *cont_c2_c1 + 1;


  // Decrypt the ciphertext
  int pt_len = client_ct_len;
  unsigned char* client_pt = NULL;
  CHECK_MALLOC(client_pt, (pt_len+1), sock);
  memset(client_pt, '\0', pt_len + 1);


  result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, client_ct, client_ct_len, session_key_client, client_iv, client_aad, client_aad_len, client_pt, TAG_LEN, client_tag);
  if(!result){
    cout<<"\nError on authentication in second decrypt in read_session_message"<<endl;
    return false;
  }

  cout<<"\n---------------------------"<<endl;
  cout<<"[ Message received ]\n"<<client_pt<<"\n---------------------------\n"<<endl;

  FREE5(aad_len_byte, aad, client_pt, client_iv, client_ct);
  free(client_aad);

  return true;

}



bool send_logout_to_server(long sock, unsigned char* session_key, unsigned int* cont_cs){

  int ret = 0;

  // Encrypt the plaintext
  int pt_len = 1;
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, pt_len, sock);
  pt[0] = DUMMY_BYTE;

  int iv_len = IV_LEN;
  unsigned char* iv = generate_random_bytes(iv_len);
  if(iv == NULL){
    cout<<"\nError in send_logout_to_server because of generate_random_bytes"<<endl;
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


  // Create aad (msg_type || cont_client_server )
  int aad_len = 1 + sizeof(int);
  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);
  unsigned char* type_byte = NULL;
  CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);

  type_byte[0] = MSG_TYPE_FAKE_LOGOUT;

  memcpy(aad, type_byte, 1);
  memcpy(&aad[1], cont_byte, sizeof(int));

  // Encrypt the plaintext
  ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
  if(ct_len == -10){
    cout<<"\nError in symt_auth_encr in send_logout_to_server"<<endl;
    return false;
  }



  int msg_len = sizeof(int) + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
  unsigned char* msg = NULL;
  CHECK_MALLOC(msg, msg_len, sock);

  int payload_len = msg_len - HEADER_LEN_SESSION;
  unsigned char* payload_len_byte = NULL;
  CHECK_MALLOC(payload_len_byte, sizeof(int), sock);
  int_to_byte(payload_len, payload_len_byte);

  unsigned char* aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  int_to_byte(aad_len, aad_len_byte);

  unsigned char* ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);

  int_to_byte(ct_len, ct_len_byte);


  memcpy(msg, payload_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], aad, aad_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);


  ret = sendn(sock, msg, msg_len);
  C_CHECK_ERROR_INT(ret, sock);
  return true;

}



void* manage_reading_session(void* args_){

    int ret = 0;

    // register signal handler (to terminate the thread on logout)
    signal(SIGUSR1, signal_handler);


    my_args* my_args2 = (my_args*) args_;

    unsigned char* session_key = my_args2->session_key;
    unsigned char* session_key_client = my_args2->session_key_client;
    unsigned int* cont_server_client = my_args2->cont;
    long sock = my_args2->ssock;
    unsigned int* cont_logout_cs = my_args2->logout_cont;

    unsigned int cont_c2_c1 = 0; //cont of the comunication from c2 to c1

    bool logout = false;

    while(!logout){

      bool r = read_session_message(sock, session_key, session_key_client, cont_server_client, &cont_c2_c1);

      if(r == false){
        logout = true;
        ret = send_logout_to_server(sock, session_key, cont_logout_cs);
        if(ret == false){
          close(sock);
          exit(1);
        }
        pthread_kill(client_thread_sending, SIGUSR1);
      }
    }

    return (void*)1;

}



int send_session_message(long sock, unsigned char* session_key, unsigned char* session_key_client, unsigned int* cont_cs, unsigned int* cont_c1_c2, string txt){

  int result = 2;
  int ret = 0;

  // Encrypt the plaintext
  int pt_len = 1;
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, pt_len, sock);
  pt[0] = DUMMY_BYTE;

  int iv_len = IV_LEN;
  unsigned char* iv = NULL;
  iv = generate_random_bytes(iv_len);
  if(iv == NULL){
    cout<<"\nError in send_session_message because of generate_random_bytes"<<endl;
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
  int_to_byte((*cont_cs), cont_byte);


  *cont_cs = *cont_cs + 1;

  // Convert txt from string to unsigned char*
  int txt_len = txt.size();
  unsigned char* txt_byte = NULL;
  CHECK_MALLOC(txt_byte, txt_len, sock);
  memcpy(txt_byte, txt.c_str(), txt.size());

  int client_iv_len = IV_LEN;
  unsigned char* client_iv = NULL;
  client_iv = generate_random_bytes(client_iv_len);
  if(client_iv == NULL){
    cout<<"\nError in send_session_message because of generate_random_bytes"<<endl;
    return -1;
  }


  int client_ct_len = txt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
  unsigned char* client_ct = NULL;
  CHECK_MALLOC(client_ct, client_ct_len, sock);


  int client_tag_len = TAG_LEN;
  unsigned char* client_tag = NULL;
  CHECK_MALLOC(client_tag, client_tag_len, sock);


  unsigned char* client_cont_byte = NULL;
  CHECK_MALLOC(client_cont_byte, sizeof(int), sock);
  int_to_byte((*cont_c1_c2), client_cont_byte);

  *cont_c1_c2 = *cont_c1_c2 + 1;


  // Create aad (cont_c1_c2)
  int client_aad_len = sizeof(int);
  unsigned char* client_aad = NULL;
  CHECK_MALLOC(client_aad, client_aad_len, sock);
  memcpy(client_aad, client_cont_byte, sizeof(int));

  unsigned char* client_aad_len_byte = NULL;
  CHECK_MALLOC(client_aad_len_byte, sizeof(int), sock);
  int_to_byte(client_aad_len, client_aad_len_byte);

  // Encrypt the txt
  client_ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, txt_byte, txt_len, session_key_client, client_iv, client_aad, client_aad_len, client_ct, client_tag_len, client_tag);
  if(ct_len == -10){
    cout<<"\nError in symt_auth_encr in send_session_message"<<endl;
    return -1;
  }


  unsigned char* client_ct_len_byte = NULL;
  CHECK_MALLOC(client_ct_len_byte, sizeof(int), sock);
  int_to_byte(client_ct_len, client_ct_len_byte);


  // Create aad (msg_type || cont_client_server || client_aad_len || client_aad || client_ct_len || client_ct || client_tag || client_iv)
  int aad_len = 1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int) + client_ct_len + client_tag_len + client_iv_len;
  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);

  unsigned char* type_byte = NULL;
  CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);


  if(strcmp(txt.c_str(), "logout") == 0){
    type_byte[0] = MSG_TYPE_LOGOUT;
    result = 1;
  }
  else{
    type_byte[0] = MSG_TYPE_SESSION_MSG;
  }


  memcpy(aad, type_byte, 1);
  memcpy(&aad[1], cont_byte, sizeof(int));
  memcpy(&aad[1 + sizeof(int)], client_aad_len_byte, sizeof(int));
  memcpy(&aad[1 + sizeof(int) + sizeof(int)], client_aad, client_aad_len);
  memcpy(&aad[1 + sizeof(int) + sizeof(int) + client_aad_len], client_ct_len_byte, sizeof(int));
  memcpy(&aad[1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int)], client_ct, client_ct_len);
  memcpy(&aad[1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int) + client_ct_len], client_tag, client_tag_len);
  memcpy(&aad[1 + sizeof(int) + sizeof(int) + client_aad_len + sizeof(int) + client_ct_len + client_tag_len], client_iv, client_iv_len);


  // Encrypt the plaintext
  ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
  if(ct_len == -10){
    cout<<"\nError in symt_auth_encr in send_user_choice"<<endl;
    return -1;
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
  FREE4(client_aad, client_ct, client_iv, client_tag);
  FREE4(payload_len_byte, ct_len_byte, msg, type_byte);

  return result;

}



void* manage_sending_session(void* args_){

    // register signal handler (to terminate the thread on logout)
    signal(SIGUSR1, signal_handler);


    my_args* my_args2 = (my_args*) args_;

    unsigned char* session_key = my_args2->session_key;
    unsigned char* session_key_client = my_args2->session_key_client;
    unsigned int* cont_client_server = my_args2->cont;
    long sock = my_args2->ssock;


    unsigned int cont_c1_c2 = 0; //cont of the comunication from c1 to c2

    bool logout = false;
    bool first = true;

    cin.ignore(1);
    cin.clear();

    cout<<"\nType something to send it as a message\n"<<endl;

    while(!logout){

      string str_txt = "";
      getline(cin, str_txt);
      int r = send_session_message(sock, session_key, session_key_client, cont_client_server, &cont_c1_c2, str_txt);

      if(r == 1){ // user wants to logout
        logout = true;
        pthread_kill(client_thread_reading, SIGUSR1);
      }
      else{// some error occurred
        if(r == -1){
          delete_key(session_key, 32);
          close(sock);
          exit(1);
        }
      }

    }

        return (void*)1;

}



void delete_key(unsigned char* session_key, int key_len){

    if( (session_key == NULL) || (key_len < 0) ){
      cout<<"\nInvalid parameters to delete key"<<endl;
      return;
    }

    memset(session_key, '\0', key_len);
    free(session_key);

}
