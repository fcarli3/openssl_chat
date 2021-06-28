
#include "./../../utility.h"
#include <list>
using namespace std;



// Struct that represents a user
typedef struct usr_elem{
    bool busy;                       //state of a user
    long usr_socket;                 //socket
    string name;                     //name of the user
    unsigned char* session_key;      //session key between server and user
    unsigned int cont_server_client; //counter for message from server to client
    unsigned int cont_client_server; //counter for message from client to server
    bool decision_ready;             //variable used for synchronization
    bool decision_result;            //variable used for synchronization
} usr;



pthread_mutex_t mutex_usr_list = PTHREAD_MUTEX_INITIALIZER;
list<usr> usr_list;


//Function used to take the lock on a shared struct or variable
void LOCK_(pthread_mutex_t *mtx) {

	int err;

	if((err = pthread_mutex_lock(mtx)) != 0){
		perror("Lock ");
		pthread_exit((void*) 1);
	}

}


//Function used to release the lock on a shared struct or variable
void UNLOCK_(pthread_mutex_t *mtx) {

  int err;

	if((err = pthread_mutex_unlock(mtx)) != 0){
		perror("Unlock ");
		pthread_exit((void*) 1);
	}

}



//Function that add a user to the list
void insert_user_online(string usr_name, long sock, unsigned char* sess_key){

    //Add the user to online user list
    usr* tmp_usr = new usr;
    tmp_usr->busy = true; //assumption: all user initially are busy. They can receive a request only if, before, they say "wait for request"
    tmp_usr->name = usr_name;
    tmp_usr->usr_socket = sock;
    tmp_usr->session_key = sess_key;
    tmp_usr->cont_client_server = 0;
	  tmp_usr->cont_server_client = 0;
    tmp_usr->decision_ready = false;
    tmp_usr->decision_result = false;

    LOCK_(&mutex_usr_list);
    usr_list.push_back((*tmp_usr));
    UNLOCK_(&mutex_usr_list);

    cout<<"\nUser "<<usr_name<<" added to online list."<<endl;
}



//Function that retrieve the value of the variable decision_ready
bool get_usr_decision_ready(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            UNLOCK_(&mutex_usr_list);
            return iter->decision_ready;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in get_usr_decision_ready: user not found"<<endl;
    return false;

}



//Function that set the value of the variable decision_ready
bool set_usr_decision_ready(string usr_, bool val){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            UNLOCK_(&mutex_usr_list);
            iter->decision_ready = val;
            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in set_usr_decision_ready: user not found"<<endl;
    return false;

}



//Function that retrieve the value of the variable decision_result
bool get_usr_decision_result(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            UNLOCK_(&mutex_usr_list);
            return iter->decision_result;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in get_usr_decision_result: user not found"<<endl;
    return false;

}



//Function that set the value of the variable decision_ready
bool set_usr_decision_result(string usr_, bool val){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            UNLOCK_(&mutex_usr_list);
            iter->decision_result = val;
            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in set_usr_decision_result: user not found"<<endl;
    return false;

}



//Function that retrieve the value of the variable cont_sc
unsigned int get_usr_cont_sc(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            UNLOCK_(&mutex_usr_list);
            return iter->cont_server_client;
        }
    }

    UNLOCK_(&mutex_usr_list);


    cout<<"\nError in get_usr_cont_sc: user not found"<<endl;
    return UINT_MAX;

}



//Function that retrieve the value of the variable cont_cs
unsigned int get_usr_cont_cs(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            UNLOCK_(&mutex_usr_list);
            return iter->cont_client_server;
        }
    }

    UNLOCK_(&mutex_usr_list);


    cout<<"\nError in get_usr_cont_cs: user not found"<<endl;
    return UINT_MAX;

}



//Function that increase the value of the variable cont_sc
bool increase_usr_cont_sc(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            iter->cont_server_client = iter->cont_server_client + 1;
            UNLOCK_(&mutex_usr_list);
            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in increase_usr_cont_sc: user not found"<<endl;
    return false;
}



//Function that increase the value of the variable cont_cs
bool increase_usr_cont_cs(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {
            iter->cont_client_server = iter->cont_client_server + 1;
            UNLOCK_(&mutex_usr_list);
            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in increase_usr_cont_cs: user not found"<<endl;
    return false;
}



//Function that delete a user from the list
bool delete_from_list(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if(strcmp((iter->name).c_str(), usr_.c_str()) == 0) {

            close(iter->usr_socket);

            iter->busy = true;
            iter->name = "";
            iter->usr_socket = -1;

            if(iter->session_key != NULL){
              memset(iter->session_key, '\0', 32);
              free(iter->session_key);
            }

            iter->cont_client_server = 0;
            iter->cont_server_client = 0;
            iter->decision_ready = false;
            iter->decision_result = false;

            usr_list.erase(iter);
            UNLOCK_(&mutex_usr_list);

            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    return false;
}



//Function that retrieve the list of online users as a string
string to_string_usr_list(string current_usr){

    string str_usr_list = "";

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if((strcmp((iter->name).c_str(), current_usr.c_str()) != 0)){ //the current user is not show in the list, because he can't talk with itself
            if(iter->busy == false){
                str_usr_list = str_usr_list + iter->name + "\n";
            }
        }
    }

    UNLOCK_(&mutex_usr_list);

    return str_usr_list;

}



//Function that set the value of the variable busy
bool set_usr_state(string usr_, bool busy_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::iterator iter = usr_list.begin(); iter != usr_list.end(); ++iter){
        if((strcmp((iter->name).c_str(), usr_.c_str()) == 0)){ // Don't return the name of the current user
            iter->busy = busy_;
            UNLOCK_(&mutex_usr_list);
            return true;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in set_usr_state: user not found"<<endl;
    return false;

}



//Function that retrieve the value of the variable session_key
unsigned char* get_usr_session_key(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if((strcmp((iter->name).c_str(), usr_.c_str()) == 0)){
            UNLOCK_(&mutex_usr_list);
            return iter->session_key;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in get_usr_session_key: user not found"<<endl;
    return NULL;

}



//Function that retrieve the value of the variable usr_socket
long get_usr_socket(string usr_){

    LOCK_(&mutex_usr_list);

    for(std::list<usr>::const_iterator iter = usr_list.cbegin(); iter != usr_list.cend(); ++iter){
        if((strcmp((iter->name).c_str(), usr_.c_str()) == 0)){
            UNLOCK_(&mutex_usr_list);
            return iter->usr_socket;
        }
    }

    UNLOCK_(&mutex_usr_list);

    cout<<"\nError in get_usr_socket: user not found"<<endl;
    return -1;

}
