#include "./../../crypto_functions/crypto_functions.cpp"
#include "./../../perfect_forward_secrecy.cpp"
#include "./../../utility.cpp"
#include <signal.h>


// Global variables that represent the threads of client that send and receive message for the chat session
extern pthread_t client_thread_reading;
extern pthread_t client_thread_sending;



int main(){

    // Ignore SIGINT
    signal(SIGINT, SIG_IGN);

    bool b_ret = false;
    long sock = 0;

    // Create a socket
    struct sockaddr_in serv_addr;
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to server
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Counters with server (to avoid replay attack)
    unsigned int cont_client_server = 0;
    unsigned int cont_server_client = 0;

    // Take username of client
    string usr_name = "";
    cout<<"\nInsert username"<<endl;
    cin>>usr_name;

    // Send client nonce
    int nonce = send_random_nonce(sock, usr_name);

    // Read ephemeral public key from server (perfect forward secrecy)
    EVP_PKEY* eph_pubkey = read_ephemeral_public_key(sock, nonce);
    if(eph_pubkey == NULL){
      cout<<"\nError because of read_ephemeral_public_key"<<endl;
      close(sock);
      exit(1);
    }

    // Generate a random session key and send it to server
    int key_len = EVP_CIPHER_key_length(SYMMETRIC_CIPHER_EXCHANGE_K_SESS);
    unsigned char* session_key = NULL;
    session_key = generate_random_bytes(key_len);
    if(session_key == NULL){
      cout<<"\nError because of generate_random_bytes"<<endl;
      close(sock);
      exit(1);
    }

    b_ret = send_session_key(sock, session_key, eph_pubkey, usr_name);
    EVP_PKEY_free(eph_pubkey);
    if(b_ret == false){
      cout<<"\nError because of send_session_key"<<endl;
      close(sock);
      exit(1);
    }



    // Reading online user list (this is a label used to come back to this point every time it's necessary). We use the GOTO functionality
    reading_usr_list:

    // Read the list of online users
    unsigned char* usr_list_ = read_usr_list(sock, session_key, &cont_server_client);
    if(usr_list_ == NULL){
      cout<<"\nError because of read_usr_list"<<endl;
      close(sock);
      exit(1);
    }
    string usr_list = (char*) usr_list_;


    // Choose if the user wants to wait for requests or if he wants make a request
    int choice = -1;
    string s_tmp = "";

    fflush(stdin);
    cin.clear();

    // Get what user wants to do
    bool done = false;
    while(!done){
      cout<<"\nChoose what you want to do\n1: Talk with another user\n2: Wait for a request to talk\n3: Logout from server\n"<<endl;
      cin>>s_tmp;
      if( (strcmp(s_tmp.c_str(), "1") != 0) && (strcmp(s_tmp.c_str(), "2") != 0) && (strcmp(s_tmp.c_str(), "3") != 0) ){
        cout<<"\nInvalid choice!"<<endl;
      }
      else{
        done = true;
      }
    }


    if(strcmp(s_tmp.c_str(), "1") == 0){
      choice = 1;
    }
    else{
      if(strcmp(s_tmp.c_str(), "2") == 0){
        choice = 2;
      }
      else{
        choice = 3;
      }
    }


    // Manage the decision (wait, talk to, logout) of the client
    switch (choice) {

      case 1: //Usr wants to talk
      {

          // Select someone to talk with from online users list and send the choice to server
          string usr2 = select_user_to_talk(usr_list);
          b_ret = send_user_choice(sock, session_key, &cont_client_server, usr2);
          if(b_ret == false){
            cout<<"\nError because of send_user_choice"<<endl;
            close(sock);
            exit(1);
          }

          cout<<"\n"<<usr_name<<" has sent a request to talk to "<<usr2<<endl;

          unsigned char* usr2_pub_key = NULL;
          int pubkey_len = -1;
          usr2_pub_key = read_request_response(sock, &cont_server_client, session_key, &pubkey_len);

          if(usr2_pub_key == NULL){
            cout<<"\nError because of read_request_response"<<endl;
            close(sock);
            exit(1);
          }
          else{
            if(usr2_pub_key[0] == 'R'){
               cout<<"\nYour request has been rejected!"<<endl;
               goto reading_usr_list;
            }
            else{
                cout<<"\nYour request has been accepted!"<<endl;
            }
          }


          // Session key establishment with the other client (perfect forward secrecy)
          int session_key_client_len = 0;
          unsigned char* session_key_client = exchange_session_key_to_talk(sock, usr_name, usr2_pub_key, pubkey_len, &cont_server_client, &cont_client_server, session_key, &session_key_client_len);
          if(session_key_client == NULL){
            cout<<"\nError because of exchange_session_key_to_talk"<<endl;
            close(sock);
            exit(1);
          }


          // Managing session messages: create one thread for the writing part of the session and one thread for the reading part of the session
          my_args* thread_args_reading = new my_args;
          thread_args_reading->ssock = sock;

          thread_args_reading->session_key = NULL;//(unsigned char*) malloc(sizeof(unsigned char) * key_len);
          CHECK_MALLOC(thread_args_reading->session_key, key_len, sock);
          memcpy(thread_args_reading->session_key, session_key, key_len);

          thread_args_reading->session_key_client = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * session_key_client_len);
          CHECK_MALLOC(thread_args_reading->session_key_client, session_key_client_len, sock);
          memcpy(thread_args_reading->session_key_client, session_key_client, session_key_client_len);

          thread_args_reading->cont = &cont_server_client; // Thread that reads from server needs the counter from server to client
          thread_args_reading->logout_cont = &cont_client_server;



          my_args* thread_args_sending = new my_args;
          thread_args_sending->ssock = sock;

          thread_args_sending->session_key = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * key_len);
          CHECK_MALLOC(thread_args_sending->session_key, key_len, sock);
          memcpy(thread_args_sending->session_key, session_key, key_len);

          thread_args_sending->session_key_client = NULL; //(unsigned char*) malloc(sizeof(unsigned char) * session_key_client_len);
          CHECK_MALLOC(thread_args_sending->session_key_client, session_key_client_len, sock);
          memcpy(thread_args_sending->session_key_client, session_key_client, session_key_client_len);

          thread_args_sending->cont = &cont_client_server;
          thread_args_sending->logout_cont = &cont_client_server;



          pthread_create(&client_thread_reading, NULL, manage_reading_session, (void*)thread_args_reading);
          pthread_create(&client_thread_sending, NULL, manage_sending_session, (void*)thread_args_sending);
          pthread_join(client_thread_reading, NULL); //to release thread when it finish.
          pthread_join(client_thread_sending, NULL); //to release thread when it finish.

          // Erase the chat session key from client
          delete_key(session_key_client, session_key_client_len);

          goto reading_usr_list;

      }
      break;


      case 2: //Usr wants to wait for requests
      {

          //User can choose how much time to wait for a request
          cout<<"\nChoose how much time (in seconds) you want to wait (max: 360, min: 10): ";
          int timeout_wait = 30;
          cin>>timeout_wait;
          if(timeout_wait<10 || timeout_wait>360){
            timeout_wait = 30;
          }

          b_ret = send_user_choice(sock, session_key, &cont_client_server, ""); // client says to server that it will wait for a request to talk
          if(b_ret == false){
            cout<<"\nError because of send_user_choice"<<endl;
            close(sock);
            exit(1);
          }


          bool in_wait = true;
          bool response = false;
          string src_usr = "";
          unsigned char* usr2_pub_key = NULL;
          int usr2_pub_key_len = -1;


          while(in_wait){

              cout<<"\nWaiting for new requests from other users....\n"<<endl;

              set_socket_timeout(sock, timeout_wait);
              src_usr = read_incoming_request(sock, session_key, &cont_server_client); //client has received a request to talk
              if(strcmp(src_usr.c_str(), "ERR") == 0 ){
                cout<<"\nError because of read_incoming_request"<<endl;
                close(sock);
                exit(1);
              }

              //Check if the timeout on the wait for request is expired
              if(strcmp(src_usr.c_str(), "TIMEOUT_EXPIRED") == 0 ){
                cout<<"\nTimeout to wait for request is expired!"<<endl;
                set_socket_timeout(sock, 0);
                b_ret = send_timeout_expired(sock, session_key, &cont_client_server);
                if(b_ret == false){
                  cout<<"\nError because of send_timeout_expired"<<endl;
                  close(sock);
                  exit(1);
                }

                goto reading_usr_list;
              }

              set_socket_timeout(sock, 0);
              cout<<"\nYou have received a new request to talk from "<<src_usr<<"\nChoose what you want to do:\n1 - Reject\n2 - Accept\n"<<endl;

              int action = -1;
              action = get_usr_input();

              if(action == -2){
                cout<<"\nError because of get_usr_input"<<endl;
                close(sock);
                exit(1);
              }

              if(action == 2){ // Accept the request
                  in_wait = false;
                  response = true;
                  b_ret = send_request_response(sock, session_key, &cont_client_server, src_usr, response);
                  if(b_ret == false){
                    cout<<"\nError while send_request_response"<<endl;
                    close(sock);
                    exit(1);
                  }

                  usr2_pub_key = read_incoming_pub_key(sock, session_key, &cont_server_client, &usr2_pub_key_len);
                  if(usr2_pub_key == NULL){
                    cout<<"\nError while read_incoming_pub_key"<<endl;
                    close(sock);
                    exit(1);
                  }

              }
              else{ // Refuse the request
                  response = false;
                  b_ret = send_request_response(sock, session_key, &cont_client_server, src_usr, response);
                  if(b_ret == false){
                    cout<<"\nError while send_request_response"<<endl;
                    close(sock);
                    exit(1);
                  }
              }

          }

          int session_key_client_len = 0;
          unsigned char* session_key_client = exchange_session_key_to_wait(sock, usr_name, session_key, usr2_pub_key, usr2_pub_key_len, &cont_server_client, &cont_client_server, &session_key_client_len);
          if(session_key_client == NULL){
              cout<<"\nError while exchange_session_key_to_wait"<<endl;
              close(sock);
              exit(1);
          }


          // Managing session messages: create one thread for the writing part of the session and one thread for the reading part of the session
          my_args* thread_args_reading = new my_args;
          thread_args_reading->ssock = sock;

          thread_args_reading->session_key = NULL; 
          CHECK_MALLOC(thread_args_reading->session_key, key_len, sock);
          memcpy(thread_args_reading->session_key, session_key, key_len);

          thread_args_reading->session_key_client = NULL;
          CHECK_MALLOC(thread_args_reading->session_key_client, session_key_client_len, sock);
          memcpy(thread_args_reading->session_key_client, session_key_client, session_key_client_len);

          thread_args_reading->cont = &cont_server_client; // Thread that reads from server needs the counter from server to client
          thread_args_reading->logout_cont = &cont_client_server;



          my_args* thread_args_sending = new my_args;
          thread_args_sending->ssock = sock;

          thread_args_sending->session_key = NULL;
          CHECK_MALLOC(thread_args_sending->session_key, key_len, sock);
          memcpy(thread_args_sending->session_key, session_key, key_len);

          thread_args_sending->session_key_client = NULL;
          CHECK_MALLOC(thread_args_sending->session_key_client, session_key_client_len, sock);
          memcpy(thread_args_sending->session_key_client, session_key_client, session_key_client_len);

          thread_args_sending->cont = &cont_client_server;
          thread_args_reading->logout_cont = &cont_client_server;



          pthread_create(&client_thread_reading, NULL, manage_reading_session, (void*)thread_args_reading);
          pthread_create(&client_thread_sending, NULL, manage_sending_session, (void*)thread_args_sending);
          pthread_join(client_thread_reading, NULL); //to release thread when it finish.
          pthread_join(client_thread_sending, NULL); //to release thread when it finish.

          delete_key(session_key_client, session_key_client_len);

          goto reading_usr_list;

      }
      break;

      case 3: //User wants to log out from server
      {

          b_ret = send_user_choice(sock, session_key, &cont_client_server, "LOGOUT");
          if(b_ret == false){
            cout<<"\nError while send_user_choice"<<endl;
          }

          close(sock);
          delete_key(session_key, key_len);
          cout<<"\nLogging out from server..."<<endl;
          exit(1);

        break;
      }

      default:
      {
          cout<<"\nDefault case. Some error occured while reading the choice from input (invalid choice)"<<endl;
          close(sock);
          exit(1);

      }
      break;
    }

    return 0;
}
