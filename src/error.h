// Errors in OpenSSL API functions 
#define CRYPTO_CHECK_ERROR(arg) \
if(!(arg)){cout<<"\nError during crypto function operations"<<endl; return -10;}



// Errors in allocation of a buffer 
#define CHECK_MALLOC(buff_ptr, len, sock) \
buff_ptr = (unsigned char*) malloc(sizeof(unsigned char) * len); \
memset(buff_ptr, '\0', len); \
if(!buff_ptr){cerr<<strerror(errno); ERR_print_errors_fp(stderr); if(sock != -1){ close(sock);} cout<<"\nCritical error on malloc: terminating client."<<endl; exit(1);}



// Client Errors
#define C_CHECK_ERROR(arg, sock) \
if(!(arg)){cerr<<strerror(errno); ERR_print_errors_fp(stderr); if(sock != -1){ close(sock);} cout<<"\nCritical error: terminating client."<<endl; exit(1);}

#define C_CHECK_ERROR_INT(arg, sock) \
if(arg == -1){cerr<<strerror(errno); ERR_print_errors_fp(stderr); if(sock != -1){ close(sock);} cout<<"\nCritical error: terminating client."<<endl; exit(1);}

#define C_CHECK_READ(arg, sock) \
if(arg == -1){cerr<<strerror(errno); ERR_print_errors_fp(stderr); if(sock != -1){ close(sock);} cout<<"\nCritical error on socket: terminating client."<<endl; exit(1);}



// Server Errors
#define S_CHECK_ERROR(arg, sock) \
if(!(arg)){cerr<<strerror(errno); ERR_print_errors_fp(stderr); if(sock != -1){ close(sock);} cout<<"\nCritical error: terminating server's thread."<<endl; pthread_exit((void*)1);}

#define S_CHECK_ERROR_INT(arg, val) \
if(arg == -1){cerr<<strerror(errno); ERR_print_errors_fp(stderr); cout<<"\nCritical error on server's thread."<<endl; return val;}




