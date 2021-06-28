#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include <openssl/bio.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "error.h"
#include "macro.h"

using namespace std;


/* Function used to handle a generated signal
 * param signum --> generated signal
 */
void signal_handler(int signum);


/* Function used to read from a socket a certain amount of bytes and store them in a buffer
 * param fd -> socket
 * param buf -> buffer where bytes are stored
 * param size -> bytes to read from the socket
 * return -> number of bytes read
 */
int readn(long fd, void *buf, size_t size);


/* Function used to send on a socket a certain amount of bytes from a buffer
 * param fd -> socket
 * param buf -> buffer from which the bytes are taken
 * param size -> bytes to send on the socket
 * return -> number of bytes sent
 */
int sendn(long fd, void *buf, size_t size);


/* Function used to set a timeout on a socket
 * param sock -> socket where to set timeout
 * param timer -> timeout
 */
void set_socket_timeout(long sock, int timer);


/* Function used to read a public key from a .pem file
 * param file_name -> path of the file
 * return -> public key in EVP_PKEY* format
 */
EVP_PKEY* read_pub_key(string file_name);


/* Function used to read a private key from a .pem file
 * param file_name -> path of the file
 * return -> private key in EVP_PKEY* format
 */
EVP_PKEY* read_private_key(string file_name);


/* Function used to convert an int into an unsigned char*
 * param i -> int to convert
 * param c -> buffer where the converted int is stored
 */
void int_to_byte(int i, unsigned char* c);


/* Function used to convert an unsigned int into an unsigned char*
 * param i -> unsigned int to convert
 * param c -> buffer where the converted int is stored
 */
void unsigned_int_to_byte(unsigned int i, unsigned char* c);


/* Function used to read a certificate from a .pem file
 * param cert_file_path -> path of the file
 * param buff_cert_size -> size of the certificate
 * return -> a buffer that contains the certificate in bytes
 */
unsigned char* read_certificate(string cert_file_path, int* buff_cert_size);


/* Function used to deserialize a certificate
 * param cert_buff -> buffer that contains the certificate in bytes
 * param cert_size -> size of the certificate
 * return -> a certificate in X509* format
 */
X509* deserialize_cert(unsigned char* cert_buff, int cert_size);


/* Function used to print the content of a certificate
 * param server_cert -> certificate in X509* format
 */
void print_Server_cert_info(X509* server_cert);


/* Function used to get an EVP_PKEY* from bytes of a public key
 * param public_key -> bytes of the public key
 * param len -> size of the buffer that contains the bytes
 * return -> a public key in EVP_PKEY* format
 */
EVP_PKEY* get_public_key_to_PKEY(unsigned char* public_key, int len);


/* Function used to get an EVP_PKEY* from bytes of a private key
 * param priv_key -> bytes of the private key
 * param len -> size of the buffer that contains the bytes
 * return -> a private key in EVP_PKEY* format
 */
EVP_PKEY* get_private_key_to_PKEY(unsigned char* priv_key, int len);


/* Function used to get bytes of a public key from an EVP_PKEY*
 * param public_key -> public key in EVP_PKEY* format
 * param pub_key_len -> size of the buffer that will contain the bytes
 * return -> buffer that contains the bytes of the public key
 */
unsigned char* get_public_key_to_byte(EVP_PKEY *public_key, int* pub_key_len);


/* Function used to read the list of online users
 * param sock -> socket
 * param session_key -> session key between client and server
 * param cont -> counter to avoid replay attacks
 * return -> buffer that contains the list of online users in bytes, or NULL in case of errors
 */
unsigned char* read_usr_list(long sock, unsigned char* session_key, int* cont);


/* Function used to select a user from the list of online users. The name of the user is provided from input
 * param usr_online_list -> list of online users
 * return -> string of the selected user, or an empty string in case the selected user isn't in the list
 */
string select_user_to_talk(string usr_online_list);


/* Function used to send the choice of the user (1: talk to someone, 2: wait for requests, 3: logout)
 * param sock -> socket
 * param session_key -> session key between client and server
 * param cont -> counter to avoid replay attacks
 * param usr_to_talk -> name of the user selected from the list
 * return -> true if the message is sent correctly, false otherwise
 */
bool send_user_choice(long sock, unsigned char* session_key, unsigned int* cont, string usr_to_talk);


/* Function used to read new requests
 * param sock -> socket
 * param session_key -> session key between client and server
 * param cont -> counter to avoid replay attacks
 * return -> name of the user that sent the request, or a specific string in case of errors or timeout expiration
 */
string read_incoming_request(long sock, unsigned char* session_key, unsigned int* cont);


/* Function used to send the response of a request
 * param sock -> socket
 * param k_sess -> session key between client and server
 * param cont -> counter to avoid replay attacks
 * param usr_of_request -> name of the user that sent the request
 * param response -> parameter used to differentiate the messagr type in case of acceptance or rejection of a request
 * return -> true if the message is sent correctly, false otherwise
 */
bool send_request_response(long sock, unsigned char* k_sess, unsigned int* cont, string usr_of_request, bool response);


/* Function used to get the response of the user and simulate the timeout
 * return -> an int that represents the response of the user
 */
int get_usr_input();


/* Function used to read the response of a request
 * param sock -> socket
 * param cont -> counter to avoid replay attacks
 * param session_key -> session key between client and server
 * param pubkey_len -> size of the public key of the user that sent the response (only in case of positive response)
 * return -> public key (in bytes) of the user that sent the response, or NULL in case of rejection or errors
 */
unsigned char* read_request_response(long sock, unsigned int* cont, unsigned char* session_key, int* pubkey_len);


/* Function used to read the public key of the user that sent a request to talk
 * param sock -> socket
 * param session_key -> session key between client and server
 * param usr2_pub_key_len -> size of the public key of the user
 * return -> public key (in bytes) of the user, or NULL in case of errors
 */
unsigned char* read_incoming_pub_key(long sock, unsigned char* session_key, unsigned int* cont, int* usr2_pub_key_len);


/* Function used to exchange a session key with another client: This function is used by a client that previously chose to wait for new requests
 * param sock -> socket
 * param usrname -> name of the user that receives the request
 * param session_key -> session key between client and server
 * param usr2_pub_key -> public key of the user that sent the request
 * param usr2_pubkey_len -> size of the public key of the user that sent the request
 * param cont_sc -> counter of the communication from server to client to avoid reply attacks
 * param cont_cs -> counter of the communication from client to server to avoid reply attacks
 * param K_sess_client_len -> size of the session key that will be established between clients
 * return -> session key (in bytes) between clients, or NULL in case of errors
 */
unsigned char* exchange_session_key_to_wait(long sock, string usrname, unsigned char* session_key, unsigned char* usr2_pub_key, int usr2_pubkey_len, unsigned int* cont_sc, unsigned int* cont_cs, int* K_sess_client_len);


/* Function used to exchange a session key with another client: This function is used by a client that previously chose to send a request to talk with another client
 * param sock -> socket
 * param username -> name of the user that send the request
 * param session_key -> session key between client and server
 * param usr2_pub_key -> public key of the user that received the request
 * param usr2_pubkey_len -> size of the public key of the user that received the request
 * param cont_sc -> counter of the communication from server to client to avoid reply attacks
 * param cont_cs -> counter of the communication from client to server to avoid reply attacks
 * param session_key -> session key generated from the client that sent the request, it will be sent to the other client
 * param session_key_client_len -> size of the session key that will be established between clients
 * return -> session key (in bytes) between clients, or NULL in case of errors
 */
unsigned char* exchange_session_key_to_talk(long sock, string username, unsigned char* usr2_pub_key, int usr2_pub_key_len, unsigned int* cont_sc, unsigned int* cont_cs, unsigned char* session_key, int* session_key_client_len);


/* Function used to read a message of the session between two clients
 * param sock -> socket
 * param session_key -> session key between client and server
 * param session_key_client -> session key between clients
 * param cont_sc -> counter of the communication from server to client to avoid reply attacks
 * param cont_c2_c1 -> counter of the communication from client2 to client 1 to avoid reply attacks
 * return -> true if the read will be done properly, false otherwise
 */
bool read_session_message(long sock, unsigned char* session_key, unsigned char* session_key_client, unsigned int* cont_sc, unsigned int* cont_c2_c1);


/* Function used to inform the thread that manage a user that he wants to terminate a session with another user
 * param sock -> socket
 * param session_key -> session key between client and server
 * param cont_cs -> counter of the communication from client to server to avoid reply attacks
 * return -> true if the sent will be done properly, false otherwise
 */
bool send_logout_to_server(long sock, unsigned char* session_key, unsigned int* cont_cs);


/* Function used by the client thread that manage the reading part of the session
 * param args -> struct that contains some useful informations about the session with the other user (e.g. counters, session key, etc...)
 */
void* manage_reading_session(void* args_);


/* Function used to send a message of the session between two clients
 * param sock -> socket
 * param session_key -> session key between client and server
 * param session_key_client -> session key between clients
 * param cont_cs -> counter of the communication from client to server to avoid reply attacks
 * param cont_c1_c2 -> counter of the communication from client1 to client2 to avoid reply attacks
 * param txt -> message that will be sent (taken from input)
 * return -> -1 in case of errors, 1 in case of logout, 2 in case of a message of the session
 */
int send_session_message(long sock, unsigned char* session_key, unsigned char* session_key_client, unsigned int* cont_cs, unsigned int* cont_c1_c2, string txt);


/* Function used by the client thread that manage the sending part of the session
 * param args -> struct that contains some useful informations about the session with the other user (e.g. counters, session key, etc...)
 */
void* manage_sending_session(void* args_);


/* Function used to delete a session key at the end of the session or in case of logout of a user
 * param session_key -> session key
 * param key_len -> size of the session key
 */
void delete_key(unsigned char* session_key, int key_len);


/* Function used in case of expiration of a timeout
 * param sock -> socket
 * param session_key -> session key between client and server
 * param cont -> counter to avoid replay attacks
 * return -> true if there are no errors, false otherwise
 */
bool send_timeout_expired(long sock, unsigned char* session_key, unsigned int* cont);
