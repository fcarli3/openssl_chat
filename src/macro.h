
//Port to connect sockets
#define PORT 1234


//Macro to deallocate memory
#define FREE2(a, b) { free(a); free(b); }

#define FREE3(a, b, c) { free(a); free(b); free(c); }

#define FREE4(a, b, c, d) { free(a); free(b); free(c); free(d); }

#define FREE5(a, b, c, d, e) { free(a); free(b); free(c); free(d); free(e); }


//Macro for ciphers, encryption modes, IV and tag lengths
#define SIGNATURE_ALGORITHM EVP_sha256()

#define SYMMETRIC_CIPHER_EXCHANGE_K_SESS EVP_aes_256_cbc()

#define SYMMETRIC_CIPHER_SESSION EVP_aes_256_gcm()

#define IV_LEN EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_SESSION)

#define IV_LEN_ENVELOPE EVP_CIPHER_iv_length(SYMMETRIC_CIPHER_EXCHANGE_K_SESS)

#define TAG_LEN 16



#define HEADER_LEN_SESSION 4

#define HEADER_LEN 5

#define DUMMY_BYTE 'y'



// Timeout for the acceptance of a request
#define TIMEOUT_RESPONSE 60



//Paths of server certificate and server private key
#define SERVER_CERT_PATH "../Server_ChatApp_certificate.pem"

#define SERVER_PRIV_KEY_PATH "./../Server_ChatApp_private_key.pem"



//Paths of CA's certificate and CA's CRL
#define CA_CERT_FILE_PATH "../CA_cert.pem"

#define CA_CRL_FILE_PATH "../CA_revocation_list.pem"



//Message types
#define MSG_TYPE_NONCE '1' // perfect forward secrecy M1

#define MSG_TYPE_EPH_PUBKEY '2' // perfect forward secrecy M2

#define MSG_TYPE_SESSION_KEY '3' // perfect forward secrecy M3

#define MSG_TYPE_SESSION_MSG '4' // generic message exchanged by two client in session

#define MSG_TYPE_USRS_LIST '5' //Server sends usrs' online list

#define MSG_TYPE_REQUEST_TO_TALK '6' //Client sends to server the request to talk with an other user

#define MSG_TYPE_FORWARD_REQUEST_TO_TALK '7' //Server forwards a request to talk to the dest_usr

#define MSG_TYPE_SESSION_KEY_RESULT '8' // OK/NO from client to server (result of session key enstabilishment)

#define MSG_TYPE_CLIENT_WAIT '9' // Client tells server that he wants to wait for requests.

#define MSG_TYPE_REQUEST_REFUSED 'A' // Request to talk refused due to usr busy/not online/he refused/timer expired

#define MSG_TYPE_REQUEST_ACCEPTED 'B' // Request to talk accepted

#define MSG_TYPE_EXCHANGE_USR_PUB_KEY 'C' // Msg that contains the usr_1 pub key (where usr_1 is the user that usr_2 wants to talk with)

#define MSG_TYPE_FORWARD_REQUEST_ACCEPT 'D' // Msg of accepted request, forwarded from server to client that sent the request

#define MSG_TYPE_FORWARD_REQUEST_REFUSED 'E' // Msg of refused request, forwarded from server to client that sent the request

#define MSG_TYPE_TIMEOUT_EXPIRED 'Z' // Msg of expired timeout for the acceptance of a request to talk

#define MSG_TYPE_LOGOUT 'F' // Msg of logout of a client from a chat session

#define MSG_TYPE_FAKE_LOGOUT 'K' // Msg of logout sent from client to its server's thread (to end that thread)
