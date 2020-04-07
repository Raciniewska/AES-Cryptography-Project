#include <stdio.h>
#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <malloc.h>
#include <string.h>
#include <string>

using namespace std;

#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1  /*for error output == -1 */
#define BUFFER 1024  /*buffer for reading messages*/
#define PORT "1209"

/*creating and setting up a ssl context structure*/
SSL_CTX* InitServerCTX(void) {	

	const SSL_METHOD* method;
	SSL_CTX* ctx;
	
	SSL_library_init();
	OpenSSL_add_all_algorithms();   //load & register all cryptos, etc.
	SSL_load_error_strings();		//lading error messeges
	
	method = TLSv1_1_server_method(); //create new server-method instance
	ctx = SSL_CTX_new(method); //create new context from method
	
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	
	return ctx;
}

/*to load z certificate into an SSL_CTX structure*/
void LoadCertificates(SSL_CTX*ctx, char* cert_file, char* key_file) {

	/*to set the local certirficate from cert_file, certificate contains PUBLIC KEY*/
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	
	/*to set the PRIVATE KEY fromkey_file*/
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		abort();
	}

	/*to verify private key*/
	if (!SSL_CTX_check_private_key(ctx)) {
		cout << "Private key does not match th epublic certificate" << endl;
		abort();
	}
}

int main() {
	SSL_CTX* ctx;
	int sever;
	const char* port_number;
	port_number = PORT;

	ctx = InitServerCTX();
	return 0;
}