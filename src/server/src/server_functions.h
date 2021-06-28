#include "./../../crypto_functions/crypto_functions.h"
#include "./../../utility.h"

using namespace std;


/* Function used to send the list of online users
 * param current_usr -> name of the user to send the list
 * param sock -> socket
 * return -> true if the sent will be done properly, false otherwise
 */
bool send_usrs_online(string current_usr, long sock);


/* Function used to check the state of a user in the list
 * param usr_ -> name of the user to check
 * return -> true if the state is set to busy, false otherwise
 */
bool check_usr_state(string usr_);


/* Function used to read the choice of the user
 * param sock -> socket
 * param choice -> choice of the user (1: talk to someone, 2: wait for requests, 3: logout)
 * param current_usr -> name of the user
 * return -> name of the user in case of choice 1, a dummy byte in case of choice 2 or NULL in case of errors
 */
unsigned char* read_usr_choice(long sock, int* choice, string current_usr);


/* Function used to send the rejection of a request
 * param src_sock -> socket
 * param current_usr -> name of the user
 * return -> true if the sent will be done properly, false otherwise
 */
bool send_request_refused(long src_sock, string current_usr);


/* Function used to forward a request to talk to another client
 * param usr2 -> user to send the request to talk
 * param current_usr -> name of the user that send the request
 * return -> true if the sent will be done properly, false otherwise
 */
bool forward_request_to_talk(string usr2, string current_usr);


/* Function used to wait for the response of a request
 * param sock -> socket
 * param current_usr -> name of the user that send the response
 * param fun_ret -> variable where it will be stored the choice of the user (false: reject, true: accept)
 * return -> user that made the request, or "ERR" in case of errors
 */
string wait_for_client_decision(long sock, string current_usr, bool* fun_ret);


/* Function used to forward a response of a request to the client that previously made the request
 * param usr_that_make_request -> user that made the request
 * param usr_that_receive_request -> user that received the request
 * param ret -> paramater used to represents the response
 * return -> true if the sent will be done properly, false otherwise
 */
bool forward_decision(string usr_that_make_request, string usr_that_receive_request, bool ret);


/* Function used to send a public key to a client after he accepted the request
 * param usr_that_make_request -> user that made the request
 * param usr_that_receive_request -> user that received and accepted the request
 * return -> true if the sent will be done properly, false otherwise
 */
bool send_pub_key(string usr_that_make_request, string usr_that_receive_request);


/* Function used to manage the establishment of the session key between two client. This function manages the client who sends the request to talk
 * param usr_name -> user that made the request
 * param usr_2 -> user that received and accepted the request
 * return -> true if the key establishment will be performed well, false otherwise
 */
bool create_session_key_usr_talk(string usr_name, string usr_2);


/* Function used to manage the establishment of the session key between two client. This function manages the client who receives the request
 * param usr_name -> user that made the request
 * param usr_2 -> user that received and accepted the request
 * return -> true if the key establishment will be performed well, false otherwise
 */
bool create_session_key_usr_to_wait(string usr_name, string usr_2);


/* Function used to manage the session between two clients. It reads the message from a client and forwards it to the other client
 * param usr_name -> user that send the message
 * param usr_2 -> user that will receive the message
 * return -> -1 in case of errors, -2 in case a user wants to end the session, 0 otherwise
 */
int read_and_forward_session(string usr_name, string usr_2);


/* Function used to manage a client with a dedicated thread
 * param client_fd -> socket
 */
void* Client_management(void* client_fd);
