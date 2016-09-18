#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>


int create_socket(char[], BIO *);

int main() {

  char          dest_url[] = "https://www.google.com";
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int ret, i;

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();


  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

 
  if(SSL_library_init() < 0)
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

 
  method = SSLv23_client_method();

  /*  create a new SSL context  */

  if ( (ctx = SSL_CTX_new(method)) == NULL)
    BIO_printf(outbio, "Unable to create a new SSL context structure!\n");

 /*Disabling SSLv2 will leave v3 and TSLv1 for negotiation */
 
 SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

 
  ssl = SSL_new(ctx);


  server = create_socket(dest_url, outbio);
  if(server != 0)
    BIO_printf(outbio, "Successfully made the TCP connection to: %s\n", dest_url);

 
  SSL_set_fd(ssl, server);


  if ( SSL_connect(ssl) != 1 )
    BIO_printf(outbio, "Error: Could not build a SSL session to: %s\n", dest_url);
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s\n", dest_url);

  /* Get the remote certificate into the X509 */

  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    BIO_printf(outbio, "Error: Could not get a certificate from: %s\n", dest_url);
  else
    BIO_printf(outbio, "Retrieved the server's certificate from: %s\n", dest_url);

  /*extract certificate information   */
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

 
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");


  SSL_free(ssl);
  close(server);
  X509_free(cert);
  SSL_CTX_free(ctx);
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s\n", dest_url);
  return(0);
}


int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char      proto[6] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  struct sockaddr_in dest_addr;


  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

  strncpy(proto, url_str, (strchr(url_str, ':')-url_str));


  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));


  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
  }

  port = atoi(portnum);

  if ( (host = gethostbyname(hostname)) == NULL ) {
    BIO_printf(out, "Error: Cannot resolve hostname %s\n",  hostname);
    abort();
  }

  /* Create TCP connection */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

 
  memset(&(dest_addr.sin_zero), '\0', 8);

  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  /* Try to make the host connect */

  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d\n",
             hostname, tmp_ptr, port);
  }

  return sockfd;
}
