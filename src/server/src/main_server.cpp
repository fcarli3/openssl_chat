#include "server_functions.cpp"
#include "./../../crypto_functions/crypto_functions.cpp"
#include "./../../utility.cpp"

#include <mutex>
#include <condition_variable>
#include <thread>

using namespace std;


// condition variable for user online list
extern pthread_mutex_t mutex_usr_list;

// list of online users
extern std::list<usr> usr_list;



int main(){

    int ret = 0;

    int server_fd;
    long client_socket;
    int val_read;

    struct sockaddr_in server_address;

    int opt = 1;
    int addr_len = sizeof(server_address);

    // Creating a socket fd for the server
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Setting socket address and port
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    // Binding socket to PORT
    ret = bind(server_fd, (struct sockaddr *)&server_address, sizeof(server_address));

    // Listen for incoming request on the socket
    ret = listen(server_fd, 5);

    cout<<"\nServer is ready for connections..."<<endl;

    while(true){

            client_socket = accept(server_fd, (struct sockaddr *)&server_address, (socklen_t*)&addr_len); //blocking

            cout<<"\nNew Client connected"<<endl;

            // Create a thread for that client
            pthread_t client_thread;
            pthread_create(&client_thread, NULL, Client_management, (void*)client_socket);
            pthread_detach(client_thread); //to release thread when it finish.
    }


}
