#include <iostream>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
using namespace std;

struct SSLConnection
{
	SSL* ssl;
	int socketfd;
};

/*SSL settings*/
void ctx_init(SSL_CTX** ctx, const SSL_METHOD* method)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	*ctx = SSL_CTX_new(method);
	if(*ctx == NULL) // ctx creation failed
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
}

void privateKey_gen(EVP_PKEY** pkey)
{
	*pkey = EVP_PKEY_new();
	RSA* rsa;
	rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	EVP_PKEY_assign_RSA(*pkey, rsa);
}

void cert_gen(EVP_PKEY** pkey, X509** crt)
{
	/*generate certificate*/
	*crt = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(*crt), 1); //sets Serial number to 1
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);//start from current time
	X509_gmtime_adj(X509_get_notAfter(*crt), 31536000L);//crt due 1 yr later
	X509_set_pubkey(*crt, *pkey);
	X509_NAME * name;
	name = X509_get_subject_name(*crt);
	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"TW", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"NTUIM", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Sophia", -1, -1, 0);
	X509_set_issuer_name(*crt, name);
	X509_sign(*crt, *pkey, EVP_sha1());
}

/*loading certificate in*/
int load_certificates(SSL_CTX** ctx, X509** crt, EVP_PKEY** pkey)
{
	if(SSL_CTX_use_certificate(*ctx, *crt) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if(SSL_CTX_use_PrivateKey(*ctx, *pkey) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if(!SSL_CTX_check_private_key(*ctx))
	{
		cerr << "Private key and certificate does not match!" << endl;
		return -1;
	}
	return 0;
}

void show_certs(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
       	cout << "Certificate information:" << endl;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
       	cout << "Subject: " << line << endl;
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        cout << "Issuer: " << line << endl;
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificate information！\n");
}