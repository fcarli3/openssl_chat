#include "server_functions.h"
#include "./../../perfect_forward_secrecy.cpp"
#include <list>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <unistd.h>

using namespace std;



// condition variable for user online list
extern pthread_mutex_t mutex_usr_list;
// list of online users
extern std::list<usr> usr_list;

condition_variable decision_cv;
mutex mutex_decision;




bool send_usrs_online(string current_usr, long sock){

    int ret = 0;

    // Serialize the list
    string str_usr_list = to_string_usr_list(current_usr);

    // Get the session key between server and the current user
    unsigned char* session_key = get_usr_session_key(current_usr);
    if(session_key == NULL){
      cout<<"\nError in send_usrs_online because of get_usr_session_key"<<endl;
      return false;
    }

    // Create plaintext : list
    int pt_len = strlen(str_usr_list.c_str());
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);
    copy(str_usr_list.begin(), str_usr_list.end(), pt);

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      return false;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);

    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, tag_len, sock);

    // AAD = (msgtype || cont_server_client)
    int aad_len = 1 + sizeof(int);
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);

    unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
    unsigned int cont = get_usr_cont_sc(current_usr);
    unsigned_int_to_byte(cont, cont_byte);

    //increasing the server-client counter to use it in the next message from server to clients
    increase_usr_cont_sc(current_usr);

    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_USRS_LIST;

    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));


    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in send_usrs_online because of sym_auth_encr"<<endl;
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

    cout<<"\nSending list to "<<current_usr<<endl;
    ret = sendn(sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);


    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);
    FREE2(aad_len_byte, aad);

    return true;
}


//check if usr is free (not busy) and if so set his state to busy
bool check_usr_state(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if( (strcmp((iter->name).c_str(), usr_.c_str()) == 0) && (iter->busy == false) ){
            iter->busy = true;
            UNLOCK_(&mutex_usr_list);
            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nSome error occurred: user not found"<<endl;
    return false;

}



unsigned char* read_usr_choice(long sock, int* choice, string current_usr){

    int ret = 0;

    unsigned char* session_key = get_usr_session_key(current_usr);

    // Reading message header (payload_len)
    unsigned char* rcv_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_LEN_SESSION);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    S_CHECK_ERROR_INT(ret, NULL);

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int


    // Read aad
    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    ret = readn(sock, aad_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, NULL);
    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len from byte to int

    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    readn(sock, aad, aad_len);


    // Read ct
    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    ret = readn(sock, ct_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, NULL);
    unsigned int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    ret = readn(sock, ct, ct_len);
    S_CHECK_ERROR_INT(ret, NULL);


    // Read tag
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * TAG_LEN);
    ret = readn(sock, tag, TAG_LEN);
    S_CHECK_ERROR_INT(ret, NULL);


    // Read iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = (unsigned char*) malloc(sizeof(unsigned char) * iv_len);
    ret = readn(sock, iv, iv_len);
    S_CHECK_ERROR_INT(ret, NULL);


    // Read msg_type
    char msg_type = (char) aad[0];
    if((msg_type != MSG_TYPE_REQUEST_TO_TALK) && (msg_type != MSG_TYPE_CLIENT_WAIT) && (msg_type != MSG_TYPE_LOGOUT)){
        cerr<<"\nError: invalid message type in read_usr_choice"<<endl;
        return NULL;
    }


    //Convert cont from byte to int
    unsigned int cont = 0;
    memcpy(&cont, &aad[1], sizeof(int));
    increase_usr_cont_cs(current_usr);


    // Decrypt the ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', ct_len + 1);
    ret = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(ret == -1) {
    	cout<<"Error: tag mismatch in read_usr_choice"<<endl;
	return NULL;
    }


    if( msg_type == MSG_TYPE_REQUEST_TO_TALK ){ //user wants to send a request to talk to someone, in the payload there will be the user who wants to talk with
        *choice = 1;
        FREE5(rcv_buff, ct_len_byte, ct, tag, iv);

        int usr_len = aad_len - sizeof(int);
        unsigned char* usr = NULL;
        CHECK_MALLOC(usr, usr_len, sock);
        memset(usr, '\0', usr_len);
        memcpy(usr, &aad[1 + sizeof(int)], usr_len);

        return usr;
    }
    else{
        if(msg_type == MSG_TYPE_LOGOUT){
          *choice = 2;

          return pt;
        }
    }

    *choice = 0;
    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);

    return pt; //dummy byte (0)

}



bool send_request_refused(long src_sock, string current_usr){

    int ret = 0;

    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, src_sock);

    unsigned char* session_key = get_usr_session_key(current_usr);
    if(session_key == NULL){
      cout<<"\nError in send_request_refused because of get_usr_session_key"<<endl;
      return false;
    }

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError in send_request_refused because of generate_random_bytes"<<endl;
      return false;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, src_sock);

    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, tag_len, src_sock);


    int aad_len = 1 + sizeof(int);
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, src_sock);

    unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), src_sock);
    unsigned int cont = get_usr_cont_sc(current_usr);
    unsigned_int_to_byte(cont, cont_byte);


    // Create the message to send: aad (msgtype || cont_sc)
    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), src_sock);
    type_byte[0] = (unsigned char) MSG_TYPE_REQUEST_REFUSED;
    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));
    increase_usr_cont_sc(current_usr);

    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in send_request_refused because of sym_auth_decr"<<endl;
      return false;
    }

    // Create the message to send
    int msg_len = HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;

    int payload_len = msg_len - HEADER_LEN_SESSION;
    unsigned char* payload_len_byte = NULL;
    CHECK_MALLOC(payload_len_byte, sizeof(int), src_sock);
    int_to_byte(payload_len, payload_len_byte);


    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), src_sock);
    int_to_byte(ct_len, ct_len_byte);


    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), src_sock);
    int_to_byte(aad_len, aad_len_byte);


    unsigned char* msg = NULL;
    CHECK_MALLOC(msg, msg_len, src_sock);

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], (unsigned char*) aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    ret = sendn(src_sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);

    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);

    return true;

}



bool forward_request_to_talk(string usr2, string current_usr){

    int ret = 0;
    long sock = get_usr_socket(current_usr);

    // Encrypt the plaintext
    int pt_len = strlen(current_usr.c_str()); //user that wants to talk
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);

    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    iv = generate_random_bytes(iv_len);
    if(iv == NULL){
        cout<<"\nError in forward_request_to_talk because of generate_random_bytes"<<endl;
        return false;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);


    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, tag_len, sock);


    int aad_len = 1 + sizeof(int);
    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);


    unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
    unsigned int cont = get_usr_cont_sc(usr2); //cont of the client to which the request is forwarding
    unsigned_int_to_byte(cont, cont_byte);


    // Create the message to send: aad (msgtype || cont_sc_2)
    unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
    type_byte[0] = (unsigned char) MSG_TYPE_FORWARD_REQUEST_TO_TALK;
    memcpy(aad, type_byte, 1);
    memcpy(&aad[1], cont_byte, sizeof(int));
    increase_usr_cont_sc(usr2);


    // Create the message to send: plaintext (current_usr)
    copy(current_usr.begin(), current_usr.end(), pt); // insert the name of who did the request

    // Encrypt the plaintext
    unsigned char* usr2_Ksess = get_usr_session_key(usr2);
    if(usr2_Ksess == NULL){
      cout<<"\nError in send_request_refused because of get_usr_session_key"<<endl;
      return false;
    }

    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, usr2_Ksess, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in send_request_refused because of get_usr_session_key"<<endl;
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
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], (unsigned char*) aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    long usr2_sock = get_usr_socket(usr2);
    if(usr2_sock == -1){
      cout<<"\nError in send_request_refused because of usr2_sock"<<endl;
      return false;
    }

    ret = sendn(usr2_sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);

    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);

    return true;

}



string wait_for_client_decision(long sock, string current_usr, bool* fun_ret){

    int ret = 0;

    // Reading message header (payload_len)
    unsigned char* rcv_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_LEN_SESSION);
    ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
    S_CHECK_ERROR_INT(ret, "ERR");

		unsigned char* session_key = get_usr_session_key(current_usr);

    int payload_dim = 0;
    memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting byte to int


    // Read aad
    unsigned char* aad_len_byte = NULL;
    CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
    ret = readn(sock, aad_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, "ERR");
    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len from byte to int

    unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
    ret = readn(sock, aad, aad_len);
    S_CHECK_ERROR_INT(ret, "ERR");

    // Reading msg_type
    char msg_type = (char) aad[0];
    if( MSG_TYPE_REQUEST_ACCEPTED != msg_type && MSG_TYPE_REQUEST_REFUSED != msg_type && MSG_TYPE_LOGOUT != msg_type && MSG_TYPE_TIMEOUT_EXPIRED != msg_type){
        cerr<<"Error: invalid message type in wait_for_client_decision"<<endl;
        return "ERR";
    }

    //Check on counter (before the decrypt and before the check of tag [authenticity])
    int cont_cs = 0; //counter received from client
    memcpy(&cont_cs, &aad[1], sizeof(int));


    if( cont_cs != get_usr_cont_cs(current_usr) ){
        cerr<<"Error: invalid cont in wait_for_client_decision"<< endl;
        return "ERR";
    }

    increase_usr_cont_cs(current_usr);


    // Read ct
    unsigned char* ct_len_byte = NULL;
    CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
    ret = readn(sock, ct_len_byte, sizeof(int));
    S_CHECK_ERROR_INT(ret, "ERR");
    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting byte to int

    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);
    ret = readn(sock, ct, ct_len);
    S_CHECK_ERROR_INT(ret, "ERR");


    // Read tag
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, TAG_LEN, sock);
    ret = readn(sock, tag, TAG_LEN);
    S_CHECK_ERROR_INT(ret, "ERR");


    // Read iv
    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    CHECK_MALLOC(iv, iv_len, sock);
    ret = readn(sock, iv, iv_len);
    S_CHECK_ERROR_INT(ret, "ERR");


    // Decrypt the ciphertext
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, ct_len, sock);
    ret = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(ret == -1 || ret == -10){
      cout<<"\nError in wait_for_client_decision because of sym_auth_decr"<<endl;
      return "ERR";
    }

    FREE5(rcv_buff, ct_len_byte, ct, tag, iv);

    if(msg_type == MSG_TYPE_REQUEST_ACCEPTED){
        *fun_ret = true;
    }
    else{

      *fun_ret = false;
      if(MSG_TYPE_TIMEOUT_EXPIRED == msg_type){
        return "TIMEOUT_EXPIRED";
      }
    }

    int usrname_len = aad_len - 1 - sizeof(int);
    unsigned char* rcv_usrname = NULL;
    CHECK_MALLOC(rcv_usrname, (usrname_len+1), sock);
    memset(rcv_usrname, '\0', (usrname_len + 1));
    memcpy(rcv_usrname, &aad[1 + sizeof(int)], usrname_len);

    return (char*) rcv_usrname; //user that made the request

}



bool forward_decision(string usr_that_make_request, string usr_that_receive_request, bool ret){

    int fun_ret = 0;
    long sock = get_usr_socket(usr_that_receive_request);
    if(sock == -1){
      cout<<"\nError in forward_decision because of get_usr_socket"<<endl;
      return false;
    }

    // Retrieve socket and session key of destination usr
    long dst_sock = get_usr_socket(usr_that_make_request);
    if(dst_sock == -1){
      cout<<"\nError in forward_decision because of get_usr_socket"<<endl;
      return false;
    }

    unsigned char* dst_Ksess = get_usr_session_key(usr_that_make_request);
    if(dst_Ksess == NULL){
      cout<<"\nError in forward_decision because of get_usr_session_key"<<endl;
      return false;
    }

		string usr_that_receive_request_key_path = "";
		EVP_PKEY* usr_that_receive_request_pub_key = NULL;
		int usr_that_receive_request_pub_key_len = 0;
		unsigned char* usr_that_receive_request_pub_key_byte = NULL;

		if(ret){
			// Retrieve the public key of usr_that_receive_request
			usr_that_receive_request_key_path = "./../pub_keys/" + usr_that_receive_request + "_public_key.pem";
			usr_that_receive_request_pub_key = read_pub_key(usr_that_receive_request_key_path);
      if(usr_that_receive_request_pub_key == NULL){
        cout<<"\nError in forward_decision because of read_pub_key"<<endl;
        return false;
      }
			usr_that_receive_request_pub_key_byte = get_public_key_to_byte(usr_that_receive_request_pub_key, &usr_that_receive_request_pub_key_len);
		}


    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);
    pt[0] = DUMMY_BYTE;


    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError in forward_decision because of generate_random_bytes"<<endl;
      return false;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    CHECK_MALLOC(ct, ct_len, sock);


    int tag_len = TAG_LEN;
    unsigned char* tag = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    CHECK_MALLOC(tag, tag_len, sock);


		// Create the aad and the message type: (ret==true ==> aad:(cont||kpub)      ret==false ==> aad:(cont))
		int aad_len = -1;
		unsigned char* cont_byte = NULL; //(unsigned char*) malloc(sizeof(int));
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
		unsigned int cont = get_usr_cont_sc(usr_that_make_request);
		unsigned_int_to_byte(cont, cont_byte);
		unsigned char* type_byte = NULL; //(unsigned char*) malloc(sizeof(unsigned char));
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);

		unsigned char* aad = NULL;

		if(ret){ // Request accepted
			aad_len = 1 + sizeof(int) + usr_that_receive_request_pub_key_len;
			aad = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * aad_len);
      CHECK_MALLOC(aad, aad_len, sock);

      type_byte[0] = (unsigned char) MSG_TYPE_FORWARD_REQUEST_ACCEPT;

      memcpy(aad, type_byte, 1);
			memcpy(&aad[1], cont_byte, sizeof(int));
	    memcpy(&aad[1 + sizeof(int)], usr_that_receive_request_pub_key_byte, usr_that_receive_request_pub_key_len);

			unsigned char* usr_that_receive_request_pub_key_len_byte = NULL; //(unsigned char*) malloc(sizeof(unsigned char*) * sizeof(int));
      CHECK_MALLOC(usr_that_receive_request_pub_key_len_byte, sizeof(int), sock);
	    int_to_byte(usr_that_receive_request_pub_key_len, usr_that_receive_request_pub_key_len_byte);

		}
		else{ // Request refused
			aad_len = 1 + sizeof(int);
			aad = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * aad_len);
      CHECK_MALLOC(aad, aad_len, sock);

      type_byte[0] = (unsigned char) MSG_TYPE_FORWARD_REQUEST_REFUSED;

			memcpy(aad, type_byte, 1);
      memcpy(&aad[1], cont_byte, sizeof(int));
		}

		increase_usr_cont_sc(usr_that_make_request);

    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, dst_Ksess, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in forward_decision because of sym_auth_encr"<<endl;
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
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
		memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    fun_ret = sendn(dst_sock, msg, msg_len);
    S_CHECK_ERROR_INT(fun_ret, false);

    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);


    return true;

}



bool send_pub_key(string usr_that_make_request, string usr_that_receive_request){

    int ret = 0;

    // Retrieve socket and session key of user_that_receive_request
    long sock = get_usr_socket(usr_that_receive_request);
    if(sock == -1){
      cout<<"\nError in send_pub_key because of get_usr_socket"<<endl;
      return false;
    }


    unsigned char* session_key = get_usr_session_key(usr_that_receive_request);
    if(session_key == NULL){
      cout<<"\nError in send_pub_key because of get_usr_session_key"<<endl;
      return false;
    }


		// Retrieve the public key of usr_that_make_request
		string usr_that_make_request_key_path = "./../pub_keys/" + usr_that_make_request + "_public_key.pem";
		EVP_PKEY* usr_that_make_request_pub_key = read_pub_key(usr_that_make_request_key_path);
    if(usr_that_make_request_pub_key == NULL){
      cout<<"\nError in send_pub_key because of read_pub_key"<<endl;
      return false;
    }


		int usr_that_make_request_pub_key_len = 0;
		unsigned char* usr_that_make_request_pub_key_byte = NULL;
    usr_that_make_request_pub_key_byte = get_public_key_to_byte(usr_that_make_request_pub_key, &usr_that_make_request_pub_key_len);
    if(usr_that_make_request_pub_key_byte == NULL){
      cout<<"\nError in send_pub_key because of get_public_key_to_byte"<<endl;
      return false;
    }


    // Encrypt the plaintext
    int pt_len = 1;
    unsigned char* pt = NULL;
    CHECK_MALLOC(pt, pt_len, sock);


    int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
    unsigned char* iv = NULL;
    iv = generate_random_bytes(iv_len);
    if(iv == NULL){
      cout<<"\nError in send_pub_key because of generate_random_bytes"<<endl;
      return false;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(SYMMETRIC_CIPHER_SESSION);
    unsigned char* ct = NULL;
    CHECK_MALLOC(ct, ct_len, sock);


    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    CHECK_MALLOC(tag, tag_len, sock);


		// Create the aad (cont || kpub)
		unsigned char* cont_byte = NULL;
    CHECK_MALLOC(cont_byte, sizeof(int), sock);
		unsigned int cont = get_usr_cont_sc(usr_that_receive_request);
		unsigned_int_to_byte(cont, cont_byte);


		int aad_len = sizeof(int) + usr_that_make_request_pub_key_len;
		unsigned char* aad = NULL;
    CHECK_MALLOC(aad, aad_len, sock);
		memcpy(aad, cont_byte, sizeof(int));
    memcpy(&aad[sizeof(int)], usr_that_make_request_pub_key_byte, usr_that_make_request_pub_key_len);


		unsigned char* usr_that_make_request_pub_key_len_byte = NULL;
    CHECK_MALLOC(usr_that_make_request_pub_key_len_byte, sizeof(int), sock);
    int_to_byte(usr_that_make_request_pub_key_len, usr_that_make_request_pub_key_len_byte);


		unsigned char* type_byte = NULL;
    CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
		type_byte[0] = (unsigned char) MSG_TYPE_EXCHANGE_USR_PUB_KEY;


		increase_usr_cont_sc(usr_that_receive_request);


    //Create the plaintext
    memcpy(pt, type_byte, 1);

    // Encrypt the plaintext
    ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == -10){
      cout<<"\nError in send_pub_key because of sym_auth_encr"<<endl;
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
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
		memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    ret = sendn(sock, msg, msg_len);
    S_CHECK_ERROR_INT(ret, false);

    FREE5(pt, iv, ct, tag, cont_byte);
    FREE4(payload_len_byte, ct_len_byte, msg, type_byte);


    return true;

}



bool create_session_key_usr_talk(string usr_name, string usr_2){

    bool ret = false;

	  ret = read_and_forward_M_1_1(usr_name, usr_2);
    if(ret == false){
      cout<<"\nError in create_session_key_usr_talk because of read_and_forward_M_1_1"<<endl;
      return false;
    }

    ret = read_and_forward_M_3_1(usr_name, usr_2);
    if(ret == false){
      cout<<"\nError in create_session_key_usr_talk because read_and_forward_M_3_1"<<endl;
      return false;
    }

    return true;

}



bool create_session_key_usr_to_wait(string usr_name, string usr_2){

    bool ret = false;

    ret = read_and_forward_M_2_1(usr_name, usr_2);
    if(ret == false){
      cout<<"\nError in create_session_key_usr_to_wait because read_and_forward_M_2_1"<<endl;
      return false;
    }

    return true;

}



int read_and_forward_session(string usr_name, string usr_2){

  int ret = 0;
  int function_result = 0;

  long sock = get_usr_socket(usr_name);
  if(sock == -1){
    cout<<"Error in read_and_forward_session of get_usr_socket"<<endl;
    return -1;
  }

  unsigned char* session_key = get_usr_session_key(usr_name);
  if(session_key == NULL){
    cout<<"Error in read_and_forward_session of get_usr_session_key"<<endl;
    return -1;
  }

  unsigned int cont_cs = get_usr_cont_cs(usr_name);

  // Reading message header (payload_len)
  unsigned char* rcv_buff = NULL;
  CHECK_MALLOC(rcv_buff, HEADER_LEN_SESSION, sock);
  ret = readn(sock, rcv_buff, HEADER_LEN_SESSION);
  S_CHECK_ERROR_INT(ret, -1);

  int payload_dim = 0;
  memcpy(&payload_dim, rcv_buff, sizeof(int)); //Converting rcv_buff from byte to int

  // Read aad
  unsigned char* aad_len_byte = NULL;
  CHECK_MALLOC(aad_len_byte, sizeof(int), sock);
  ret = readn(sock, aad_len_byte, sizeof(int));
  S_CHECK_ERROR_INT(ret, -1);
  int aad_len = 0;
  memcpy(&aad_len, aad_len_byte, sizeof(int)); //Converting aad_len_byte from byte to int

  unsigned char* aad = NULL;
  CHECK_MALLOC(aad, aad_len, sock);
  ret = readn(sock, aad, aad_len);
  S_CHECK_ERROR_INT(ret, -1);


  // Read ct
  unsigned char* ct_len_byte = NULL;
  CHECK_MALLOC(ct_len_byte, sizeof(int), sock);
  ret = readn(sock, ct_len_byte, sizeof(int));
  S_CHECK_ERROR_INT(ret, -1);

  int ct_len = 0;
  memcpy(&ct_len, ct_len_byte, sizeof(int)); //Converting ct_len_byte from byte to int

  unsigned char* ct = NULL;
  CHECK_MALLOC(ct, ct_len, sock);
  ret = readn(sock, ct, ct_len);
  S_CHECK_ERROR_INT(ret, -1);


  // Read tag
  unsigned char* tag = NULL;
  CHECK_MALLOC(tag, TAG_LEN, sock);
  ret = readn(sock, tag, TAG_LEN);
  S_CHECK_ERROR_INT(ret, -1);


  // Read iv
  int iv_len = EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION);
  unsigned char* iv = NULL;
  CHECK_MALLOC(iv, iv_len, sock);
  ret = readn(sock, iv, iv_len);
  S_CHECK_ERROR_INT(ret, -1);


   //Check the counter
  unsigned int rcv_cont = 0;
  memcpy(&rcv_cont, &aad[1], sizeof(unsigned int));


  if(rcv_cont != cont_cs) {
    cerr<<"Error: invalid cont in read_and_forward_session --> client NONCE"<<endl;
    return -1;
  }

  increase_usr_cont_cs(usr_name);


  // Read msg_type
  char msg_type = (char) aad[0];
  if( MSG_TYPE_SESSION_MSG != msg_type){
      if(msg_type == MSG_TYPE_LOGOUT){
        cout<<"\nUser "<<usr_name<<" wants to logout."<<endl;
      }
      else{
        if(msg_type == MSG_TYPE_FAKE_LOGOUT){ //Telling server's thread of this user to end the session
          return -2;
        }
        else{
          cerr<<"Error: invalid msg_type in read_and_forward_session"<<endl;
          return -1;
        }
      }
      function_result = -2;
  }


  // Decrypt the ciphertext
  unsigned char* pt = NULL;
  CHECK_MALLOC(pt, ct_len, sock);
  int result = sym_auth_decr(SYMMETRIC_CIPHER_SESSION, ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
  if(result == -1 || result == -10){
    cerr<<"ERROR on authentication, read_and_forward_session"<<endl;
    return -1;
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
    cout<<"Error in read_and_forward_session of generate_random_bytes"<<endl;
    return -1;
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


  // Create aad (msg_type || cont_client_server || client_aad_len || client_aad || client_ct_len || client_ct || client_tag || client_iv)
  int client_aad_len = 1 + sizeof(int) + msg_client_len;
  unsigned char* client_aad = NULL;
  CHECK_MALLOC(client_aad, client_aad_len, sock);

  unsigned char* type_byte = NULL;
  CHECK_MALLOC(type_byte, sizeof(unsigned char), sock);
  type_byte[0] = msg_type;
  memcpy(client_aad, type_byte, 1);
  memcpy(&client_aad[1], cont_sc_byte, sizeof(int));
  memcpy(&client_aad[1 + sizeof(int)], msg_client, msg_client_len);

  increase_usr_cont_sc(usr_2);

  // Encrypt the plaintext
  unsigned char* session_key_usr2 = get_usr_session_key(usr_2);
  if(session_key_usr2 == NULL){
    cout<<"Error in read_and_forward_session in get_usr_session_key for session_key_usr2"<<endl;
    return -1;
  }

  ct_len = sym_auth_encr(SYMMETRIC_CIPHER_SESSION, pt, pt_len, session_key_usr2, iv, client_aad, client_aad_len, ct, TAG_LEN, tag);
  if(ct_len == -10){
    cout<<"Error in read_and_forward_session in sym_auth_encr"<<endl;
    return -1;
  }

  // Create the message to send
  int msg_len = HEADER_LEN_SESSION + sizeof(int) + client_aad_len + sizeof(int) + ct_len + TAG_LEN + iv_len;
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
  int_to_byte(client_aad_len, aad_len_byte);


  unsigned char* msg = NULL;
  CHECK_MALLOC(msg, msg_len, sock);

  memcpy(msg, rcv_buff, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION], aad_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int)], client_aad, client_aad_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + client_aad_len], ct_len_byte, sizeof(int));
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + client_aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + client_aad_len + sizeof(int) + ct_len], (unsigned char*) tag, TAG_LEN);
  memcpy((unsigned char*) &msg[HEADER_LEN_SESSION + sizeof(int) + client_aad_len + sizeof(int) + ct_len + TAG_LEN], (unsigned char*) iv, iv_len);

  long dst_sock = get_usr_socket(usr_2);
  if(dst_sock == -1){
    cout<<"Error in read_and_forward_session in get_usr_socket of dst_sock"<<endl;
    return -1;
  }

  ret = sendn(dst_sock, msg, msg_len);
  S_CHECK_ERROR_INT(ret, -1);

  FREE5(pt, iv, ct, tag, cont_sc_byte);
  FREE4(rcv_buff, ct_len_byte, msg, type_byte);

  return function_result;

}


//Client management
void* Client_management(void* client_fd){

    bool error_val = false;
    long fd = (long) client_fd;


    // Reading client nonce
    int nonce = 0;
    string usrname = read_nonce(fd, &nonce);
    if(strcmp(usrname.c_str(), "ERR") == 0){
      cout<<"Error in Client_management because of read_nonce"<<endl;
      cout<<"Shutting down server's thread of client"<<endl;
      close(fd);
      pthread_exit((void*) 1);
    }


    //Read client's public key
		EVP_PKEY* pubK = read_pub_key("./../pub_keys/" + usrname + "_public_key.pem");
    if(pubK == NULL){
      cout<<"\nError in Client_management because of read_pub_key (usrname: "<<usrname<<")"<<endl;
      cout<<"Shutting down server's thread of "<<usrname<<endl;
      close(fd);
      pthread_exit((void*) 1);
    }


    // Generate ephemeral keys and send the public one
    EVP_PKEY* ephemeral_public_key = NULL;
    EVP_PKEY* ephemeral_private_key = NULL;
    generate_ephemeral_keys(&ephemeral_private_key, &ephemeral_public_key);
    if(ephemeral_private_key == NULL || ephemeral_public_key == NULL){
      cout<<"Error in Client_management because of generate_ephemeral_keys (usrname: "<<usrname<<")"<<endl;
      cout<<"Shutting down server's thread of "<<usrname<<endl;
      close(fd);
      pthread_exit((void*) 1);
    }


    // Send ephemeral public key
    error_val = send_ephemeral_public_key(fd, ephemeral_public_key, nonce);
    if(error_val == false){
      cout<<"Error in Client_management because of send_ephemeral_public_key (usrname: "<<usrname<<")"<<endl;
      cout<<"Shutting down server's thread of "<<usrname<<endl;
      close(fd);
      pthread_exit((void*) 1);
    }


    // Reading the session key
    int session_key_len = -1;
    unsigned char* session_key = read_session_key(fd, ephemeral_private_key, ephemeral_public_key, usrname, &session_key_len);
    EVP_PKEY_free(ephemeral_private_key);
    EVP_PKEY_free(ephemeral_public_key);
    if(session_key == NULL){
        cout<<"Error in Client_management because of read_session_key (usrname: "<<usrname<<")"<<endl;
        cout<<"Shutting down server's thread of "<<usrname<<endl;
        close(fd);
        pthread_exit((void*)1);
    }


    // Add a user to the list and send user online list to client
    insert_user_online(usrname, fd, session_key);


    // Start point of the real functionality of this thread
    start_point:
    set_usr_state(usrname, true);
    set_usr_decision_result(usrname, false);
    set_usr_decision_ready(usrname, false);

    usleep(500000); //0.5 seconds, to syncronize client's thread and its server thread's
    error_val = send_usrs_online(usrname, fd);
    if(error_val == false){
      cout<<"\nError in Client_management because of send_usrs_online (usrname: "<<usrname<<")"<<endl;
      delete_from_list(usrname);
      pthread_exit((void*) 1);
    }


    // Read client decision
    int choice = -1;
    unsigned char* tmp = read_usr_choice(fd, &choice, usrname);
    if(tmp == NULL){
      cout<<"\nError in Client_management because of read_usr_choice (usrname: "<<usrname<<")"<<endl;
      delete_from_list(usrname);
      pthread_exit((void*) 1);
    }


    string usr_2 = (char*) tmp;
    switch (choice) {

      case 1: //usrname has chosen to talk to usr_2
      {
            bool usr_2_state = check_usr_state(usr_2);

            if(usr_2_state == false){ //User busy or not present in the list

                cout<<"\nError: the user "<<usr_2<<" is busy or is not in the list!"<<endl;
                error_val = send_request_refused(fd, usrname);
                if(error_val == false){
                  cout<<"\nError in Client_management because of send_request_refused (usrname: "<<usrname<<")"<<endl;
                  delete_from_list(usrname);
                  pthread_exit((void*) 1);
                }

                goto start_point;
            }
            else{

                set_usr_state(usr_2, true); //set immediatly user 2 state (busy)
                error_val = forward_request_to_talk(usr_2, usrname); // send the request to talk from thread of usr_name to client usr_2
                if(error_val == false){
                  cout<<"\nError in Client_management because of forward_request_to_talk (usrname: "<<usrname<<")"<<endl;
                  delete_from_list(usrname);
                  pthread_exit((void*) 1);
                }

                //The thread waits for the decision of the other client
                {
                  unique_lock<mutex> lock_decision(mutex_decision);
                  while(!get_usr_decision_ready(usr_2)){
                    decision_cv.wait(lock_decision);
                  }
                }

                if(get_usr_decision_result(usr_2) == true){
                  error_val = create_session_key_usr_talk(usrname, usr_2);
                  if(error_val == false){
                    cout<<"\nError in Client_management because of create_session_key_usr_talk (usrname: "<<usrname<<")"<<endl;
                    delete_from_list(usrname);
                    pthread_exit((void*) 1);
                  }
                }
                else{

                 cout<<"\n(usrname: "<<usrname<<") Request refused... back to send list"<<endl;
                 set_usr_decision_ready(usr_2, false);
                 set_usr_decision_result(usr_2, false);
                 goto start_point;
               }

            }


        break;
      }

      case 0: //usrname has chosen to wait for requests from other clients
      {
          cout<<"\n(username: "<<usrname<<") Thread waiting..."<<endl;

    				set_usr_state(usrname, false); //user is waiting, so ists state has to be set free
    				bool ret = false;
    				string usr2 = "";
    				bool in_wait = true;

    				// Cycle untile someone made a request to us
    				while(in_wait){

    						cout<<"\n(username: "<<usrname<<") is waiting for request..."<<endl;
    						ret = false;
    						usr2 = wait_for_client_decision(fd, usrname, &ret); //Thread del server attende che l'utente decida se accettare o rifiutare una richiesta che ha ricevuto

                if(strcmp(usr2.c_str(), "ERR") == 0){
                  cout<<"Error in Client_management because of wait_for_client_decision (usrname: "<<usrname<<")"<<endl;
                  delete_from_list(usrname);
                  pthread_exit((void*)1);
                }

                usr_2 = usr2;

    						if(ret == false) { // timeout exprired or request refused
                    if(strcmp(usr2.c_str(), "TIMEOUT_EXPIRED") == 0){
                      goto start_point;
                    }

    								set_usr_state(usrname, false);
    								error_val = forward_decision(usr2, usrname, ret); // case where the thread forwards the rejection of the request
                    if(error_val == false){
                      cout<<"\nError in Client_management because of forward_decision (usrname: "<<usrname<<" - request refused)"<<endl;
                      delete_from_list(usrname);
                      pthread_exit((void*) 1);
                    }

                    {
                      unique_lock<mutex> lock_decision(mutex_decision);
                      set_usr_decision_ready(usrname, true);
                      set_usr_decision_result(usrname, false);
                      decision_cv.notify_one();
                    }

    						}
    						else{ //request accepted

    								in_wait = false; // exit from wait loop
    								set_usr_state(usrname, true);
    								error_val = forward_decision(usr2, usrname, ret); // case where the thread forwards the acceptance of the request
                    if(error_val == false){
                      cout<<"\nError in Client_management because of forward_decision (usrname: "<<usrname<<" - request accepted)"<<endl;
                      delete_from_list(usrname);
                      pthread_exit((void*) 1);
                    }

                    {
                      unique_lock<mutex> lock_decision(mutex_decision);
                      set_usr_decision_ready(usrname, true);
                      set_usr_decision_result(usrname, true);
                      decision_cv.notify_one();
                    }

                    error_val = send_pub_key(usr2, usrname); // sending the public key of the user that make the request to talk
                    if(error_val == false){
                      cout<<"\nError in Client_management because of send_pub_key (usrname: "<<usrname<<")"<<endl;
                      delete_from_list(usrname);
                      pthread_exit((void*) 1);
                    }
    						}
    				}

    				error_val = create_session_key_usr_to_wait(usrname, usr2); // Create a session key between clients

            if(error_val == false){
              cout<<"\nError in Client_management because of create_session_key_usr_to_wait (usrname: "<<usrname<<")"<<endl;
              delete_from_list(usrname);
              pthread_exit((void*) 1);
            }

      }
      break;


      case 2: //usr has chosen to logging out from the server
      {
            cout<<"\nUser "<<usrname<<" wants to disconnect from server"<<endl;
            delete_from_list(usrname);
            pthread_exit((void*) 1);

      }
      break;

      default:
      {
        cout<<"\n(username: "<<usrname<<") Error reading the choice. Disconnect the user."<<endl;
        delete_from_list(usrname);
        pthread_exit((void*) 1);
      }
      break;

    }



    //Now the clients are connected and they have the session key to talk to each other. Server thread manage the session of this clients.
    bool logout = false;

    while(!logout){

      int r = read_and_forward_session(usrname, usr_2);
      if(r == -2){
        logout = true;
        cout<<"\nThread "<<usrname<<" is logging out..."<<endl;
      }
      else{
        if(r == -1){
          logout = true;
          cout<<"\nError in Client_management because of read_and_forward_session (usrname: "<<usrname<<")"<<endl;
          delete_from_list(usrname);
          pthread_exit((void*) 1);
        }
      }
    }

    goto start_point;

}
