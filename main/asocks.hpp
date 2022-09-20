#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#ifndef ESP
#include <netinet/ip.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>
using namespace std;

#include "utils.hpp"

#define SOCK_OK 1
#define SOCK_CLOSED 0
#define SOCK_ERROR -1 //general error

#define SOCK_TIMEOUT -42
//#define SOCK_NOTHING_TO_READ -43

#define SOCK_CONNECT_RESOLVE -10

#define SOCK_CONNECT_SOCKET -20  //Socket failed
#define SOCK_CONNECT_SOCKET_CONNECT -21 //::connect() failed

#define SOCK_CONNECT_SSL_SOCKET -30
#define SOCK_CONNECT_SSL_SSL -31
#define SOCK_CONNECT_SSL_WANT_READ -32

// cb asocks
enum ascb_type_t {
  ASCB_CONNECTED, //=POLLOUT,
  ASCB_TIMEOUT,
  ASCB_DISCONNECTED, //also for FAIL
  //ASCB_DATA_AVAL //=POLLIN, //not used on asocks
};

const char *get_ascb_type_str(ascb_type_t x)
{
  //if(x==ASCB_DATA) return "ASCB_DATA";
  if(x==ASCB_CONNECTED) return "ASCB_CONNECTED";
  if(x==ASCB_TIMEOUT) return "ASCB_TIMEOUT";
  if(x==ASCB_DISCONNECTED) return "ASCB_DISCONNECTED";
  return "ASCB_?????";
}

class asocket_t {
protected:

  virtual void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][asocket %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:
  int dbg=DBGBASE;
  
  virtual bool is_connected() const =0;//{return connected;}
  virtual void disconnect() {};
  
  virtual ~asocket_t() {  }


  virtual int connect(const string& host, const short port) { //TODO NOT ASYNC !
    struct addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res=NULL;

    int err = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);

    if(err != 0 || res == NULL) {
      LOG_WARN("DNS lookup failed err=%d res=%p\n", err, res);
      //if (res != NULL) freeaddrinfo(res);
      return false;
    }

    int r=SOCK_CONNECT_RESOLVE;
    auto p=res;
    while(p && p->ai_family!=AF_INET) p=p->ai_next;
    if(p) {
      sockaddr_in *a=(sockaddr_in*)res->ai_addr;
      r=connect_ipv4(a->sin_addr, port);
    }
    
    freeaddrinfo(res);

    return r;
  }

  virtual void set_socket_options(){}

  virtual int connect_ipv4(const in_addr &address, const short port) {
    return connect(ipv4_to_string(address),port);
  }

  virtual int write(const unsigned char *data,int len)=0;

  bool write_string(const string &s) {
    int n=write((const unsigned char*)s.c_str(),s.size());
    return n==s.size();
  }

  typedef std::function<void(const unsigned char *,int l)> callback_t;
  callback_t ncb=NULL;

  void set_ncb(callback_t ncb_) {
   LOG_DEBUG("set callback %p\n",ncb_);
   ncb=ncb_;
  }
};



#include "poll.hpp"
#include <functional>

class asocket_raw_t : public asocket_t, public pollable_t {
protected:
  const int STATUS_ERROR=1<<30;
  const int STATUS_RESOLVED=1;
  const int STATUS_CONNECT=2;
  const int STATUS_RAW_CONNECTED=4;

  int connected=0;
  bool error=0;
  
  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][asocket_raw %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:
  int fd=-1;

  virtual int write(const unsigned char *data,int len) {
    return raw_write(data,len);
  }
  
  int raw_write(const unsigned char *data,int len) {
    LOG_DEBUGVV("write fd=%d len=%d\n",fd,len);

    if (error || 0==(connected & STATUS_RAW_CONNECTED)) {
      LOG_DEBUGVV("not connected =%x or error=%d !\n",connected,error);
      return SOCK_ERROR;
    }

    if (len == 0)
      return SOCK_ERROR;

    int r=send(fd, data, len, MSG_NOSIGNAL);

    if(r==0)
      LOG_SEVERE("WTF send() returns 0 !\n");
    
    if(r<0) {
      LOG_WARN("error raw_write '%s' len=%d\n",errno_str(errno).c_str(),len);
      error=1;
      return SOCK_ERROR;
    }
    
    return r;
  }

  void set_blocking() {
    int flags = fcntl(fd, F_GETFL, 0);
    flags = flags &~ O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
  }

  void set_nonblocking() {
    int flags = fcntl(fd, F_GETFL, 0);
    flags = flags | O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
  }

  int raw_read(unsigned char *data,int maxlen) {
    if (0==(connected & STATUS_RAW_CONNECTED)) return SOCK_CLOSED;
    if (error) return SOCK_ERROR;

    LOG_DEBUGVV("read fd=%d maxlen=%d\n",fd,maxlen);

#ifdef LINUX //TEST    
    struct timespec ts,ts2;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
#endif
    int r=recv(fd, data, maxlen, MSG_NOSIGNAL);
#ifdef LINUX //TEST    
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts2);
    long long dt=(ts2.tv_nsec+1000000000LL*ts2.tv_sec)-(ts.tv_nsec+1000000000LL*ts.tv_sec);
    static long long mdt=0;
    if(mdt<dt) {
      mdt=dt;
      LOG_INFO("max recv blocking time : %Ld\n",mdt);
    }
#endif    
    LOG_DEBUGVV("read fd=%d rets=%d\n",fd,r);

    if(r<0 && errno==EAGAIN) {
      LOG_DEBUG("EAGAIN in socks_raw\n");
      return SOCK_TIMEOUT;
    }

    if(r<0 && errno==EINTR) {
      LOG_DEBUG("[EINTR]\n");
      return SOCK_TIMEOUT;
    }

    if(r==0) {
      LOG_DEBUG("raw_read rets =0\n");
      disconnect();
      return 0;
    }
    if(r<0) {
      LOG_WARN("recv %s\n",errno_str(errno).c_str());
      error=1;
      return SOCK_ERROR;
    }
    return r;
  }

  void cb_pollin() {
    if(ncb) {
      unsigned char data[512];
      int r=raw_read(data,512);
      if(r<=0) {
	if(r<0)
	  LOG_WARN("r=%d <0 !\n",r);
	else
	  LOG_INFO("asocks_raw::read returns 0 : disconnected\n");
	if(ncb)
	  ncb(NULL,ASCB_DISCONNECTED);
      } else {
	ncb(data,r);
      }
    } else {
      LOG_FATAL("WTF\n");
    }
  }

  void cb_pollout() {
    connected|=STATUS_RAW_CONNECTED;
    if(ncb)
      ncb(NULL,ASCB_CONNECTED);
  }

  void cb_timeout() {
    if(ncb)
      ncb(NULL,ASCB_TIMEOUT);
  }
  
  virtual void pcallback(pollable_t **pc,poll_reg_t &r) {
    if(r.events==POLL_POLLOUT) {
      cb_pollout();
    }
    if(r.events==POLL_POLLIN) {
      cb_pollin();
    }
    if(r.events==POLL_TIMEOUT) {
      cb_timeout();
    }
  }

  
  virtual bool is_connected() const {return connected&STATUS_RAW_CONNECTED;}
  virtual void set_socket_options() {
    LOG_DEBUG("set asocket_options\n");
    
    int e=1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(e));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &e, sizeof(e));

    set_nonblocking();
  }

  void disconnect_raw() {
    LOG_INFOV("disconnect_raw\n");
    if(connected) {
      shutdown(fd, SHUT_RDWR);
      connected=0;
    }
    if(fd>=0) {
      close(fd);
      fd=-1;
    }
  }
  
  virtual void disconnect() {
    LOG_INFOV("disconnect\n");
    disconnect_raw();
  }

  virtual ~asocket_raw_t() {
    disconnect();
  }

  int setup_socket() {
    LOG_INFOV("setup_socket\n");

    if (connected) {
      disconnect();
    }

    if(fd>=0) return 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
      LOG_WARN("Failed to allocate socket: %s\n", errno_str(errno).c_str());
      return SOCK_CONNECT_SOCKET;
    }
    
    return 0;
  }

  virtual int connect_ipv4(const in_addr &address, const short port) {
    int r=setup_socket();
    if(r) return r;
    
    set_socket_options();

    sockaddr_in a;
    a.sin_family=AF_INET;
    a.sin_port=htons(port);
    a.sin_addr=address;

    //set_str_status("connect_ipv4  socket raw nonblock");
    if(::connect(fd, (const sockaddr*)&a, sizeof(a)) != 0) {
      if(errno==EINPROGRESS) {
	LOG_INFOV("async connect returns errno EINPROGRESS as expected\n");
      } else {
	LOG_WARN("Socket connection failed fd=%d, errno = %d %s \n", fd,errno,errno_str(errno).c_str());
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return SOCK_CONNECT_SOCKET_CONNECT;
      }
    }
    //set_str_status("connect async OK");
    
    connected|=STATUS_CONNECT;

    return 1;
  }
};


class asocket_tls_t : public asocket_raw_t {
protected:
  const int STATUS_TLS_CONNECT=8;
  const int STATUS_TLS_CONNECTED=16;

  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][asocket_tls %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:
  
  asocket_tls_t () {  }

  ~asocket_tls_t() {
    disconnect_tls();
  }

  /** Mbedtls SSL context */
  mbedtls_ssl_context ssl;
  /** Mbedtls SSL configuration */
  mbedtls_ssl_config conf;

  // not used ?
  // /** Mbedtls certificate chain */
  // mbedtls_x509_crt cacert;

  /** Minimum RSA key size in bits */
  unsigned short min_rsa_key_size;

  bool tls_resources_ready=0;

  void mbedtls_error(int ret,const char *s,bool rel=1) {
    char bf[128];
    mbedtls_strerror(ret, bf, 127);
    LOG_WARN("mbedtls error %s: %s\n", s,bf);
    if(rel)
      release_tls_resources();
  }
  
public:  
  void setup_tls_resources() {
    if(tls_resources_ready) return;

    // Initialize resources needed
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    //mbedtls_x509_crt_init( &cacert );

    tls_resources_ready=1;
  }

  void release_tls_resources() {
    //ca_chain_loaded = false;
    if (tls_resources_ready) {
      mbedtls_ssl_free(&ssl);
      mbedtls_ssl_config_free(&conf);
      //mbedtls_x509_crt_free(&cacert);
    }	
    tls_resources_ready=0;
  }
  
  static int net_send( void *ctx,const unsigned char *buf,size_t len ){
    asocket_tls_t *s=(asocket_tls_t*)ctx;
    int r=s->raw_write(buf,len);
    ::LOG_DEBUGVV("net send %zu : %d\n",len,r);
    return r;
  }

  static int net_recv( void *ctx,unsigned char *buf,size_t len ){
    asocket_tls_t *s=(asocket_tls_t*)ctx;
    int r=s->raw_read(buf,len);
    ::LOG_DEBUGVV("net rcv %zu : %d\n",len,r);
    if(r<0) {
      //if(r==SOCK_NOTHING_TO_READ) return MBEDTLS_ERR_SSL_WANT_READ;
      if(r==SOCK_TIMEOUT) return MBEDTLS_ERR_SSL_WANT_READ;
      //LOG(1,"error in net_send %d\n",r);
    }
    return r;
  }

#if 0 //not used ?
  bool ca_chain_loaded=0;
  void set_CA_certificate_chain_PEM(const string& pemCAcertificate) {
    setup_tls_resources();
    ca_chain_loaded = true;

    // PEM: must be null terminated, could be multiple at once
    // The size passed must include the null-terminating char
    unsigned long int CERT_SIZE = pemCAcertificate.length() + 1;
    int ret = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char*>(pemCAcertificate.c_str()), CERT_SIZE);
    if( ret < 0 )
      mbedtls_error(ret,"Failed to parse CA chain PEM certificate");
  }

  void add_CA_certificate_to_chain_DER(const vector<unsigned char>& derCAcertificate) {
    setup_tls_resources();
    ca_chain_loaded = true;

    // DER: must be JUST ONE!

    int ret = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char*>(derCAcertificate.data()), derCAcertificate.size());
    if( ret < 0 )
      mbedtls_error(ret,"Failed to parse CA chain DER certificate");
  }
#endif
  
  int setup_ssl(const string &host) {
    //set_str_status("setup_ssl");
    connected|=STATUS_TLS_CONNECT;
    
    setup_tls_resources();
    
    //set_str_status("mbedtls_ssl_config_defaults...");
    
    int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
      mbedtls_error(ret,"Failed to setup SSL socket: %s\n");
      return SOCK_CONNECT_SSL_SSL;
    }
    
    // // Set the security mode
    // if (ca_chain_loaded) {
    //   mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    //   mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    //   mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    //   LOG_DEBUG("SSL certificate chain loaded.\n");
    // } else {
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
      //mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
      mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg );
      //LOG_DEBUG("SSL with INSECURE mode set.\n");
      //}
    
    //set_str_status("mbedtls_ssl_setup...");
    
    //Setup
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret) {
      mbedtls_error(ret,"Failed to setup SSL configuration");
      return SOCK_CONNECT_SSL_SSL;
    }
    //set_str_status("mbedtls_ssl_set_hostname...");
    ret = mbedtls_ssl_set_hostname(&ssl, host.c_str());
    if (ret) {
      mbedtls_error(ret,"Failed to setup SSL hostname");
      return SOCK_CONNECT_SSL_SSL;
    }
    
    LOG_DEBUG("SSL setup done.\n");
    
    mbedtls_ssl_set_bio(&ssl, this, net_send, net_recv, NULL);
    
    return continue_setup_ssl(host);
  }

  int continue_setup_ssl(const string &host) {
    LOG_DEBUG("Performing handshake.\n");

    // Handshake
    int ret = mbedtls_ssl_handshake(&ssl);
    if(ret==MBEDTLS_ERR_SSL_WANT_READ) {
      LOG_DEBUG("MBEDTLS_ERR_SSL_WANT_READ\n");
      return SOCK_CONNECT_SSL_WANT_READ;
    }
    if(ret==MBEDTLS_ERR_SSL_WANT_WRITE) {
      LOG_WARN("unhandled MBEDTLS_ERR_SSL_WANT_WRITE\n");
    }
    if(ret==MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
      /* \return         #MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS if an asynchronous
       *                 operation is in progress (see
       *                 mbedtls_ssl_conf_async_private_cb()) - in this case you
       *                 must call this function again when the operation is ready.
       */
      LOG_WARN("unhandled MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS\n");
    }
    if(ret==MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
      /* \return         #MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS if a cryptographic
       *                 operation is in progress (see mbedtls_ecp_set_max_ops()) -
       *                 in this case you must call this function again to complete
       *                 the handshake when you're done attending other tasks.
       */
      LOG_WARN("unhandled MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS\n");
    }

    if (ret != 0) {
      mbedtls_error(ret,"Failed SSL handshake");
      return SOCK_CONNECT_SSL_SSL;
    }

    LOG_DEBUG("SSL handshake done.\n");
		
#if 0 // not used yet
    // Verify certificates, if loaded
    if (ca_chain_loaded) {
      unsigned long int flags = mbedtls_ssl_get_verify_result(&ssl);
      if (flags != 0) {
	mbedtls_error(ret,"Certificate validation failed");
	//mbedtls_x509_crt_verify_info(errBuf, ERR_BUF_SIZE - 1, "", flags);
	return SOCK_CONNECT_SSL_SSL;
      }
      LOG_DEBUG("Certificate validation success.\n");
    }
    else {
      LOG_DEBUG("Certificate are not validated (INSECURE MODE).\n");
    }
#endif
    
    LOG_INFOV("SSL connection ready.\n");

    connected|=STATUS_TLS_CONNECTED;

    return 0;
  }

  void disconnect_tls() {
    LOG_INFOV("disconnect_tls\n");
    if(connected&STATUS_TLS_CONNECTED) {
      mbedtls_ssl_close_notify(&ssl);
    }
    release_tls_resources();
    disconnect_raw();
    connected=0;
  }

  void disconnect() {
    disconnect_tls();
  }

  int write(const unsigned char *data,int len) {
    if (0==(connected&STATUS_TLS_CONNECTED)) return SOCK_CLOSED;

    if (len == 0)
      return SOCK_ERROR;

    int ret;
    do {
      ret = mbedtls_ssl_write(&ssl, data,len);

      if(ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
	mbedtls_error(ret," Failed to write",0);
	disconnect();
	return ret;
      }
    }  while (ret <= 0);
    
    LOG_DEBUG("%d bytes written.\n", ret);

    if(ret!=len)
      LOG_WARN("mbedtls_write %d / %d  bytes written !!!\n", ret,len);
      
    
    return ret;
  }

  virtual bool is_connected() const {return connected&STATUS_TLS_CONNECTED;}

  virtual int read(unsigned char *data,int maxlen) {
    if (0==(connected&STATUS_TLS_CONNECTED)) return SOCK_CLOSED;
    
    int ret=mbedtls_ssl_read(&ssl, data, maxlen);
    LOG_DEBUGVV("mbedtls_ssl_read maxlen=%d rets %d\n",maxlen,ret);
    if(ret== MBEDTLS_ERR_SSL_TIMEOUT) {
      LOG_DEBUG("timeout int tls:read\n");
      return SOCK_TIMEOUT;
    }
    
    if(ret== MBEDTLS_ERR_SSL_WANT_READ) {
      LOG_DEBUG("want_read int tls:read\n");
      return SOCK_TIMEOUT;
    }

    if (ret < 0) {
      mbedtls_error(ret,"Failed to read",0);
      return -1;
    }

    if(ret==0) {
      LOG_DEBUG("read ret=0 : disconnected\n");
      disconnect();
      return 0;
    }

    return ret;

    //T (mbedtls_ssl_get_bytes_avail(&ssl)>0);
  }

  string host="";
  int connect(const string &host_, const short port) {
    host=host_;
    return asocket_raw_t::connect(host,port);
  }

  void cb_pollin() {
    if(0==(connected&STATUS_TLS_CONNECTED)) {
      int r=continue_setup_ssl(host);
      if(r==SOCK_CONNECT_SSL_WANT_READ)
	return;
      if(r) {
	connected|=STATUS_ERROR;
	if(ncb)
	  ncb(NULL,ASCB_DISCONNECTED);
      }
      if(0==(connected&STATUS_TLS_CONNECTED))
	return;
      if(ncb)
	ncb(NULL,ASCB_CONNECTED);
    }
    if(ncb) {
      assert(0); //TODO read_tls + ncb
    }
  }
  
  void cb_pollout() {
    connected|=STATUS_RAW_CONNECTED;
    if(connected&STATUS_TLS_CONNECT) {
      LOG_FATAL("should not be here\n");
    }
    int r=setup_ssl(host);
    if(r!=SOCK_CONNECT_SSL_WANT_READ) {
      connected|=STATUS_ERROR;
      if(ncb)
	ncb(NULL,ASCB_DISCONNECTED);
    }
  }


  virtual void pcallback(pollable_t **pc,poll_reg_t &r) {
    if(r.events==POLL_POLLOUT) {
      cb_pollout();
    }
    if(r.events==POLL_POLLIN) {
      cb_pollin();
    }
    if(r.events==POLL_TIMEOUT) {
      cb_timeout();
    }
  }

  
};

struct shitty_http_server_t {
  asocket_t *sr=NULL;
  string b;
  
  void cb(const unsigned char *a,int l) {
    if(!a) {
      LOG_INFO("cb NULL %d\n",l);
      return;
    }

    char *bf=(char*)big_malloc(l+1);
    memcpy(bf,a,l);
    bf[l]=0;
    LOG_INFO("shitty_http_server got '%s\n",bf);
    for(int u=0;u<l;u++)
      if(bf[u]=='\r' || bf[u+1]=='\n') {
	LOG_INFO("shitty_http_server sends body\n");
	sr->write((const unsigned char*)b.c_str(),b.size());
	LOG_INFO("shitty_http_server sends body DONE\n");
	sr->disconnect();
	break;
      }
    big_free(bf);
  }
    
  shitty_http_server_t(asocket_t *sr_,string b_="<html><body>HELLO WORLD</body></html>\r\n")  {
    b=b_;
    sr=sr_;
    sr->set_ncb(std::bind(&shitty_http_server_t::cb,this,std::placeholders::_1,std::placeholders::_2));
  }
  
  ~shitty_http_server_t() {
    LOG_DEBUG("~shitty_http_server_t() %p\n",this);
    sr->disconnect();
    delete sr;
  }
};

shitty_http_server_t *shitty_http_server(asocket_t *sr,string b="<html><body>HELLO WORLD</body></html>\r\n")
{
  return new shitty_http_server_t(sr,b); //not nice...
}


template<unsigned int bfsize=4096>
struct aclientbuff_t {
private:
  asocket_t *sock=NULL;
  mutex_t mut;
  condvar_t cond;
  cvector_t<unsigned char,bfsize> buffer;
  bool end=0;
  int dbg=DBGBASE;

  void cb(const unsigned char *t,int l) {
    if(t) {
      mut.lock();
      while(l) {
	int k=buffer.left();
	if(k==0) {
	  mut.unlock();
	  usleep(10000); //bad !
	  mut.lock();
	  continue;
	}
	if(k>l)
	  k=l;
	assert(k<=l);
	buffer.push_back(t,k);
	cond.broadcast();
	t+=k;
	l-=k;
      }
      mut.unlock();
      return;
    }
    LOG_INFO("aclientbuff CB %d\n",l);
    if(l==ASCB_DISCONNECTED) {
      mut.lock();
      end=1;
      cond.broadcast();
      mut.unlock();
    }
  }
  

public:
  
  void set_sock(asocket_t *s) {
    if(sock)
      sock->set_ncb(NULL);
    sock=s;
    if(s)
      s->set_ncb(std::bind(&aclientbuff_t::cb,this,std::placeholders::_1,std::placeholders::_2));
  }

  ~aclientbuff_t() {
    set_sock(NULL);
  }
  
  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][clientbuff %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

  void clear() {
    if(sock)
      sock->disconnect();
    sock=NULL;
    buffer.clear();
    end=0;
  }

  int read_until(unsigned char *data,int maxlen,const char *m,int ml) {
    mut.lock();
    int wr=0;
    int pt=0;

    while(wr<maxlen) {
      LOG_DEBUG("RU wr=%d / %d | bf.size=%d\n",wr,maxlen,int(buffer.size()));
      int ret=0;
      while(!end && buffer.size()==0) {
	cond.wait(mut);
      }
      if(buffer.size()>0) {
	LOG_DEBUG("RU buffered %d\n",int(buffer.size()));
	assert(maxlen>wr);
	ret=buffer.read(data+wr,maxlen-wr);

	if(dbg>_LOG_DEBUG) {
	  printf("in buf: >>>>");
	  for(int i=0;i<ret;i++)
	    printf("%c",data[i]);
	  printf("<<<<\n");
	}
      } 
      
      LOG_DEBUG("RU rcv %d\n",ret);

      if(ret==0) {
	assert(end);
	mut.unlock();
	return wr;
      }
      
      assert(ret>0);

      while(pt+ml<=wr+ret) {
	if(0==strncmp((char*)data+pt,m,ml)) {
	  LOG_DEBUG("RU found pt=%d\n",pt);
	  int wr2=pt+ml;
	  wr+=ret;
	  LOG_DEBUG("RU wr=%d wr2=%d\n",wr,wr2);
	  if(wr2<wr) {
	    assert(buffer.left()>=wr-wr2);
	    buffer.push_front(data+wr2,wr-wr2);
	  }
	  mut.unlock();
	  return wr2;
	}
	pt++;
      }

      wr+=ret;
      LOG_DEBUG("RU got %d/%d\n",wr,maxlen);
    }

    mut.unlock();
    return wr;
  }

};



string httpheader(const string &get,const string &path,const string &host) {
  string request;

  string agent="empty";
  request.append(get+" "+path+" HTTP/1.1\r\n");
  request.append("Host: "+host+"\r\n");
  request.append("User-Agent: "+agent);
  request.append("\r\n");

  return request;
}

string httprequest(const string &path,const string &host,bool close) {
  string request=httpheader("GET",path,host);
  if(close) {
    request.append("Connection: close\r\n");
  }
  request.append("\r\n");
  
  return request;
}

string httppost(const string &path,const string &host,int len) {
  string request=httpheader("POST",path,host);
  char tmp[20];
  snprintf(tmp,20,"%d",len);
  request.append("Content-Length: ");
  request.append(tmp);
  request.append("\r\n");
  request.append("Connection: close\r\n");
  request.append("\r\n");
  
  return request;
}


bool is_ipv4(const char *bf)
{
  int p[4];
  int k=0;
  p[k++]=atoi(bf);
  for(int u=0;bf[u];u++) {
    if(bf[u]=='.') {
      if(k==4) return false;
      p[k++]=atoi(bf+u+1);
    } else
      if(bf[u]<'0' || bf[u]>'9') return false;
  }
  if(k!=4) return false;
  int s=0;
  for(int i=0;i<4;i++) {
    if(p[i]<0 || p[i]>255) return false;
    s+=p[i];
  }
  return s>0;
}

