# OpenSSL Online Chat
This repository contains the final project of Applied Cryptography course (Master's Degree in Cybersecurity at [University of Pisa](https://cysec.unipi.it/)). The project has been developed for educational purposes and represents a multithread client-server chat application in which every communication between peers is encrypted using OpenSSL APIs.

## How it works
When a client correctly connects to the server, the server will show a list of online users to this client, then the client can request a chat session with other clients. This client will wait for the peer response. As for now there are 3 users registered to the server. If you want to create your own client, you should generate a pair of 2048-bit RSA keys and the private key must be protected by password. The server has a public certificate that is granted to be safe by the CA SimpleAuthority.

## Prerequisites 
The programs needs the installation of [OpenSSL](https://github.com/openssl/openssl), a TLS/SSL and crypto library, and [SimpleAuthority](https://simpleauthority.com/), a trusted CA.

### Install on Ubuntu/Debian
First of all, install build dependencies, then clone OpenSSL and configure it.

```bash
sudo apt-get -y install build-essential checkinstall git zlib1g-dev
git clone --depth 1 --branch OpenSSL_1_1_1g https://github.com/openssl/openssl.git
cd openssl
./config zlib '-Wl,-rpath,$(LIBRPATH)'
```

After you have built and tested, install OpenSSL and configure the shared libs.

```bash
make
make test
sudo make install
sudo ldconfig -v
```
Finally, check the OpenSSL version to make sure you have successfully completed all the steps.

```bash
openssl version
```

### Install SimpleAuthority
To generate a certificate, install SimpleAuthority at the following link: [SimpleAuthority](https://simpleauthority.com/)

## 2048-bit RSA Generation
Before running the program , the user should generate a pair of 2048-bit RSA keys using OpenSSL command-line tools. 

* **RSA private key**: the following command generate a .pem file, protected by a user-chosen password, containing a 2048-bit key.

```bash
openssl genrsa -aes128 -out private_key.pem 2048
```
* **RSA public key**: a private key in OpenSSL is represented with a strcuture that contains also the public key, so the following command extract the public key from the private key.
```bash
openssl rsa -pubout -aes128 -in private_key.pem -out public_key.pem
```

## Usage
Before running the programs, you have first to compile them with `-lcrypto` flag, in order to include crypto features of OpenSSL, and `-lpthread` flag.

```bash
cd server/src
g++ main_server.cpp -lcrypto -lpthread -o server.out
./server.out

cd client/src
g++ client_test.cpp -lcrypto -lpthread -o client_test.out
./client_test.out
```

## Authors

 - [Francesco Carli](https://github.com/fcarli3)
 - [Gianluca Boschi](https://github.com/gianluca2414)
 - [Paola Petri](https://github.com/paolapetri)
