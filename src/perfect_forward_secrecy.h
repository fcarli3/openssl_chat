#include "./crypto_functions/crypto_functions.h"
#include "utility.h"


/* Function used to send a random nonce
 * param sock -> socket
 * param usr_name -> username of client
 * return -> the nonce sent
 */
int send_random_nonce(long sock, string usr_name);


/* Function used to read a random nonce and the username of client that sent it
 * param sock -> socket
 * param nonce -> addres of an int variable where the nonce that the function read will be stored
 * return -> username of client, "ERR" if error
 */
string read_nonce(long sock, int* nonce);


/* Function used to read a random nonce and the username of client that sent it
 * param prv -> addres of an EVP_PKEY variable where the private key will be stored
 * param pub -> addres of an EVP_PKEY variable where the public key will be stored
 */
void generate_ephemeral_keys(EVP_PKEY** prv, EVP_PKEY** pub);


/* Function used to send the ephemeral public key and the certificate of server
 * param sock -> socket
 * param ephemeral_pub_key -> ephemeral public key
 * param nonce -> nonce received before, included to avoid replay attack
 * return -> true if the message is sent correctly, false otherwise
 */
bool send_ephemeral_public_key(long sock, EVP_PKEY* ephemeral_pub_key, int nonce);


/* Function used to read the ephemeral public key and the certificate of server
 * param sock -> socket
 * param nonce -> nonce received before, included to avoid replay attack
 * return -> ephemeral public key if certificate verification is ok and no error occurs, NULL otherwise
 */
EVP_PKEY* read_ephemeral_public_key(long sock, int nonce);


/* Function used to send the client-server session key from client to server
 * param sock -> socket
 * param session_key -> session key between client and server
 * param usr_name -> username of client_tag
 * return -> true if no error occurs, false otherwise
 */
bool send_session_key(long sock, unsigned char* session_key, EVP_PKEY* eph_pub_key, string usr_name);


/* Function used to read the client-server session key
 * param sock -> socket
 * param eph_priv_key -> ephemeral private key
 * param eph_public_key -> ephemeral public key
 * param usr_name -> client username
 * param session_key_len -> client-server session key length
 * return -> true if no error occurs, false otherwise
 */
unsigned char* read_session_key(long sock, EVP_PKEY* eph_priv_key, EVP_PKEY* eph_public_key, string usr_name, int* session_key_len);



/* From now, number of messages will refers the relation of this project, where there are schemes that illustrates all messages exchanged */


/* Function used to send M 1.1
 * param sock -> socket
 * param session_key -> client-server session key
 * param cont -> pointer to client-server counter
 * return -> nonce value if no error occurs, -1 otherwise
 */
int send_M_1_1(long sock, unsigned char* session_key, unsigned int* cont);


/* Function used to read M 1.1 and forward it to an other client (forward M 1.1 = send M 1.2)
 * param usr_name -> client from which the server reads
 * param usr_2 -> client to which server will send
 * return ->true if no error occurs, false otherwise
 */
bool read_and_forward_M_1_1(string usr_name, string usr_2);


/* Function used to read M 1.2
 * param sock -> socket
 * param session_key -> client-server session_key
 * cont_sc -> server-client counter
 */
int read_M_1_2(long sock, unsigned char* session_key, unsigned int* cont_sc);


/* Function used to send M 2.1
 * param sock -> socket
 * param session_key -> client-server session_key
 * param cont_cs -> client-server counter
 * param eph_pubkey -> ephemeral public key
 * param usrname -> client nUsername
 * param nonce -> nonce
 * return -> true if no error occurs, false otherwise
 */
bool send_M_2_1(long sock, unsigned char* session_key, unsigned int* cont_cs, EVP_PKEY* eph_pubkey, string usrname, int nonce);


/* Function used to read M 2.1 and forward it to an other client (forward M 2.1 = send M 2.2)
 * param usr_name -> client from which the server reads
 * param usr_2 -> client to which server will send
 * return ->true if no error occurs, false otherwise
 */
bool read_and_forward_M_2_1(string usr_name, string usr_2);


/* Function used to read M 2.2
 * param sock -> socket
 * param session_key -> client-server session_key
 * param cont -> server-client counter
 * param eph_pubkey_len -> ephemeral public key length
 * param nonce -> nonce
 * param usr2_pubkey -> pther client's public key
 * param usr2_pubkey_len -> pther client's public key length
 * return -> ephemeral public key if no error occurs, NULL otherwise
 */
unsigned char* read_M_2_2(long sock, unsigned char* session_key, unsigned int* cont, int* eph_pubkey_len, int nonce, unsigned char* usr2_pubkey, int usr2_pubkey_len);


/* Function used to send M 3.1
 * param sock -> socket
 * param username -> client username
 * param session_key -> client-server session_key
 * param cont_cs -> client-server counter
 * param eph_pubkey -> ephemeral public key
 * param eph_pubkey_len -> ephemeral public key length
 * param session_client_key -> client-client session key
 * param session_client_key_len -> client-client session key length
 * return -> true if no error occurs, false otherwise
 */
bool send_M_3_1(long sock, string usrname, unsigned char* session_key, unsigned int* cont_cs, unsigned char* eph_pubkey, int eph_pubkey_len, unsigned char* session_client_key, int session_client_key_len);


/* Function used to read M 3.1 and forward it to an other client (forward M 3.1 = send M 3.2)
 * param usr_name -> client from which the server reads
 * param usr_2 -> client to which server will send
 * return ->true if no error occurs, false otherwise
 */
bool read_and_forward_M_3_1(string usr_name, string usr_2);


/* Function used to read M 3.2
 * param sock -> socket
 * param username -> client username
 * param session_key -> client-server session_key
 * param cont -> server-client counter
 * param eph_pk -> ephemeral public key
 * param eph_pb_len -> ephemeral public key length
 * param eph_privkey -> ephemeral private key length
 * param usr2_pubkey -> other client's public key
 * usr2_pubkey_len -> other client's public key length
 * pt_client_len -> plaintext length
 * return -> client-client session key if no error occurs, NULL otherwise
 */
unsigned char* read_M_3_2(long sock, string usrname, unsigned char* session_key, unsigned int* cont, unsigned char* eph_pk, int eph_pb_len, EVP_PKEY* eph_privkey, unsigned char* usr2_pubkey, int usr2_pubkey_len, int* pt_client_len);
