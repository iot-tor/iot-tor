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
#include "utils.hpp"
using namespace std;

#define SOCK_CLOSED 0
#define SOCK_ERROR -1 //general error
#define SOCK_TIMEOUT -42
//#define SOCK_NOTHING_TO_READ -43

#define SOCK_CONNECT_RESOLVE -10

#define SOCK_CONNECT_SOCKET -20  //Socket failed
#define SOCK_CONNECT_SOCKET_CONNECT -21 //::connect() failed

#define SOCK_CONNECT_SSL_SOCKET -30
#define SOCK_CONNECT_SSL_SSL -31

class socket_t {
protected:
  int timeout=0; //in MS
  int timeout_connect=0; //in MS
  void set_str_status(const string &a)
  {
    //fprintf(stderr,"[%s]  \r",a.c_str());
  }
  
  virtual void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )=0;

public:
  int dbg=DBGBASE;
  
  virtual int getfd()  const {return -1;}
  virtual bool data_in_buf() const {return 0;}
  virtual bool is_blocking() const {return timeout!=0;}
  virtual int get_timeout() const {return timeout;}
  virtual void set_timeout(int s) {timeout=timeout_connect=s;}

  virtual void set_timeout(int s,int s2) {timeout=s;timeout_connect=s2;}

  virtual bool is_connected() const =0;//{return connected;}
  
  virtual int connect(const string& host, const short port) {
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

  virtual ~socket_t() {  }

  virtual void disconnect()=0;

  virtual void set_socket_options(){}
  virtual void set_socket_options_connect(){}
  
  bool write_string(const string &s) {
    int n=write((const unsigned char*)s.c_str(),s.size());
    return n==s.size();
  }

  virtual int connect_ipv4(const in_addr &address, const short port) {
    return connect(ipv4_to_string(address),port);
  }

  virtual int write(const unsigned char *data,int len)=0;
  virtual int read(unsigned char *data,int maxlen)=0;
};


class socket_raw_t : public socket_t {
protected:
  int fd=-1;
  bool connected=0;
  bool error=0;
  
  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][socket_raw %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:
  virtual int getfd() const {return fd;}

  virtual bool is_connected() const {return connected;}
  virtual void set_socket_options() {
    //if(connected) return;
    
    int e=1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(e));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &e, sizeof(e));

    if(is_blocking()) {
      
      struct timeval timeout;
      timeout.tv_sec = this->timeout/1000;
      timeout.tv_usec = (this->timeout%1000)*1000;
      
      //printf("set timeout %d %d\n",int(timeout.tv_sec),int(timeout.tv_usec));
      
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    } else {
      int flags = fcntl(fd, F_GETFL, 0);
      flags = flags | O_NONBLOCK;
      fcntl(fd, F_SETFL, flags);
    }

    // int flags = fcntl(fd, F_GETFL, 0);
    // printf("is_blocking %d\n",is_blocking());
    // flags = is_blocking() ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    // fcntl(fd, F_SETFL, flags);

  }

  virtual void set_socket_options_connect() {
    set_socket_options();
    int e=1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(e));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &e, sizeof(e));

    if(timeout_connect) {
      struct timeval timeout;
      timeout.tv_sec = this->timeout_connect/1000;
      timeout.tv_usec = (this->timeout_connect%1000)*1000;
      
      //printf("set timeout %d %d\n",int(timeout.tv_sec),int(timeout.tv_usec));
      
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    } else {
      int flags = fcntl(fd, F_GETFL, 0);
      flags = flags | O_NONBLOCK;
      fcntl(fd, F_SETFL, flags);
    }

  }
  
  virtual ~socket_raw_t() {
    disconnect();
  }
  
  void disconnect_raw() {
    if(!connected) return;
    shutdown(fd, SHUT_RDWR);
    close(fd);
    connected=false;
  }
  
  virtual void disconnect() final {
    disconnect_raw();
  }


  int connect_ipv4(const in_addr &address, const short port) {
    if (connected) {
      disconnect();
    }

    
    sockaddr_in a;
    a.sin_family=AF_INET;
    a.sin_port=htons(port);
    a.sin_addr=address;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
      LOG_SEVERE("Failed to allocate socket.\n");
      return SOCK_CONNECT_SOCKET;
    }

    set_socket_options_connect();

    set_str_status("connect");
    if(::connect(fd, (const sockaddr*)&a, sizeof(a)) != 0) {
      LOG_WARN("Socket connection failed fd=%d, errno = %d %s timeout=%d %d\n", fd,errno,errno_str(errno).c_str(),timeout,timeout_connect);
      shutdown(fd, SHUT_RDWR);
      close(fd);
      return SOCK_CONNECT_SOCKET_CONNECT;
    }
    set_str_status("connect OK");

    set_socket_options();

    connected=true;

    return 1;
  }

  int write(const unsigned char *data,int len) {
    if (!connected) return false;
    if (error) return -1;

    if (len == 0)
      return SOCK_ERROR;

    int r=send(fd, data, len, 0);

    if(r==0)
      LOG_SEVERE("WTF send() returns 0 !\n");
    
    if(r<0) {
      LOG_INFOVV("send %s",errno_str(errno).c_str());
      error=1;
      return -1;
    }
    
    return r;
  }

  virtual int read(unsigned char *data,int maxlen) {
    if (!connected) return SOCK_CLOSED;
    if (error) return -1;

    LOG_DEBUGVV("read maxlen=%d\n",maxlen);
    //printf("read raw fd=%d\n",fd);
    
    int r=recv(fd, data, maxlen, 0);

    //printf("read raw rets %d\n",r);
    
    if(r<0 && errno==EAGAIN) {
      LOG_DEBUG("EAGAIN in socks_raw\n");
      return SOCK_TIMEOUT;
    }

    if(r<0 && errno==EINTR) {
      LOG_DEBUG("[EINTR]\n");
      return SOCK_TIMEOUT;
    }

    if(r==0) {
      disconnect();
      return 0;
    }
    if(r<0) {
      LOG_WARN("recv %s\n",errno_str(errno).c_str());
      error=1;
    }
    return r;
  }

};

class socket_tls_t : public socket_t {
  bool connected=0;
  bool own=0;

  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][socket_tls %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

public:
  
  void clearsock() {
    if(own) {
      assert(sock_);
      delete sock_;
      own=0;
    }
    if(!sock_) return;
    sock_=NULL;
  }
  
  void setsock(socket_t &s) {
    clearsock();
    sock_=&s;
  }
	      
  
  socket_tls_t () {
    sock_=new socket_raw_t();
    own=1;
  }
  
  virtual void set_timeout(int s) {timeout=s;if(sock_) sock_->set_timeout(s);}
  virtual void set_timeout(int s,int s2) {timeout=s;timeout=s2;if(sock_) sock_->set_timeout(s,s2);}

  ~socket_tls_t() {
    disconnect();
    clearsock();
  }

  /* is sock is not null uses socks
     otherwise, create/use  tls_socket
  */
      
  socket_t *sock_=NULL;

  virtual int getfd() const {
    assert(sock_);
    if(sock_) return sock_->getfd();
    return -1;
  }

  
  /** Mbedtls SSL context */
  mbedtls_ssl_context ssl;
  /** Mbedtls SSL configuration */
  mbedtls_ssl_config conf;
  /** Mbedtls certificate chain */
  mbedtls_x509_crt cacert;
  /** Minimum RSA key size in bits */
  unsigned short min_rsa_key_size;

  bool ca_chain_loaded=0;
  bool resources_ready=0;

  void mbedtls_error(int ret,const char *s,bool rel=1) {
    char bf[128];
    mbedtls_strerror(ret, bf, 127);
    LOG_WARN("mbedtls error %s: %s\n", s,bf);
    if(rel)
      release_resources();
  }
  
public:  
  void setup_resources() {
    if(resources_ready) return;

    // Initialize resources needed
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );

    resources_ready = true;
  }

  void release_resources() {
    if (connected) disconnect();
    ca_chain_loaded = false;

    if (resources_ready) {
      mbedtls_ssl_free(&ssl);
      mbedtls_ssl_config_free(&conf);
      mbedtls_x509_crt_free(&cacert);
    }	
    resources_ready = false;
  }
  
  static int net_send( void *ctx,const unsigned char *buf,size_t len ){
    socket_t *s=(socket_t*)ctx;
    int r=s->write(buf,len);
    //s->LOG(5,"net send %zu : %d\n",len,r);
    return r;
  }

  static int net_recv( void *ctx,unsigned char *buf,size_t len ){
    socket_t *s=(socket_t*)ctx;
    int r=s->read(buf,len);
    //s->LOG(5,"net rcv %zu : %d\n",len,r);
    if(r<0) {
      //if(r==SOCK_NOTHING_TO_READ) return MBEDTLS_ERR_SSL_WANT_READ;
      if(r==SOCK_TIMEOUT) return MBEDTLS_ERR_SSL_WANT_READ;
      //LOG(1,"error in net_send %d\n",r);
    }
    return r;
  }

  static int net_recv_timeout( void *ctx,unsigned char *buf,size_t len,uint32_t to){
    socket_t *s=(socket_t*)ctx;
    int r=s->read(buf,len);
    //s->LOG(4,"net rcvto %zu : %d\n",len,r);
    if(r<0) {
      //if(r==SOCK_NOTHING_TO_READ) return MBEDTLS_ERR_SSL_WANT_READ;
      if(r==SOCK_TIMEOUT) return MBEDTLS_ERR_SSL_TIMEOUT;
    }
    return r;
  }
  
  
  void set_CA_certificate_chain_PEM(const string& pemCAcertificate) {
    setup_resources();
    ca_chain_loaded = true;

    // PEM: must be null terminated, could be multiple at once
    // The size passed must include the null-terminating char
    unsigned long int CERT_SIZE = pemCAcertificate.length() + 1;
    int ret = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char*>(pemCAcertificate.c_str()), CERT_SIZE);
    if( ret < 0 )
      mbedtls_error(ret,"Failed to parse CA chain PEM certificate");
  }

  void add_CA_certificate_to_chain_DER(const vector<unsigned char>& derCAcertificate) {
    setup_resources();
    ca_chain_loaded = true;

    // DER: must be JUST ONE!

    int ret = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char*>(derCAcertificate.data()), derCAcertificate.size());
    if( ret < 0 )
      mbedtls_error(ret,"Failed to parse CA chain DER certificate");
  }
  
  int setup_ssl(const string &host) {
    set_str_status("setup_ssl\r");
    //printf("SETUP ssl sock_=%p\n",sock_);

    if(connected)
      disconnect();
    
    setup_resources();
    
    set_str_status("mbedtls_ssl_config_defaults...\r");
    
    int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
      mbedtls_error(ret,"Failed to setup SSL socket: %s\n");
      return SOCK_CONNECT_SSL_SSL;
    }
    
    // Set the security mode
    if (ca_chain_loaded) {
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
      mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
      mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg );
      LOG_DEBUG("SSL certificate chain loaded.\n");
    } else {
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
      //mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
      mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg );
      LOG_DEBUG("SSL with INSECURE mode set.\n");
    }
    
    set_str_status("mbedtls_ssl_setup...\n");
    
    //Setup
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret) {
      mbedtls_error(ret,"Failed to setup SSL configuration");
      return SOCK_CONNECT_SSL_SSL;
    }
    set_str_status("mbedtls_ssl_set_hostname...\n");
    ret = mbedtls_ssl_set_hostname(&ssl, host.c_str());
    if (ret) {
      mbedtls_error(ret,"Failed to setup SSL hostname");
      return SOCK_CONNECT_SSL_SSL;
    }
    
    LOG_DEBUG("SSL setup done.\n");
    
    assert(sock_);
    if(!is_blocking())
      mbedtls_ssl_set_bio(&ssl, sock_, net_send, net_recv, NULL);
    else {
      mbedtls_ssl_set_bio(&ssl, sock_, net_send, NULL, net_recv_timeout);
      mbedtls_ssl_conf_read_timeout(&conf, get_timeout());
    }
    
    LOG_DEBUG("Performing handshake.\n");

    // Handshake
    ret = mbedtls_ssl_handshake(&ssl);
    //if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    if (ret != 0) {
      mbedtls_error(ret,"Failed SSL handshake");
      return SOCK_CONNECT_SSL_SSL;
    }

    LOG_DEBUG("SSL handshake done.\n");
		
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

    LOG_INFOV("SSL connection ready.\n");

    connected = true;

    set_socket_options();
    
    return 1;
  }
  
  int connect(const string &host, const short port) {
    assert(sock_);
    auto r=sock_->connect(host,port);
    if(r!=1) return r;

    return setup_ssl(host);
  }

  void disconnect() final {
    if (connected) {
      connected = false;
      mbedtls_ssl_close_notify(&ssl);
      LOG_INFOV("Disconnected.\n");
    }
    release_resources();
  }

  virtual bool is_connected() const {
    if(sock_==NULL) return connected;
    return connected && sock_->is_connected();
  }

  int write(const unsigned char *data,int len) {
    if (!connected) return SOCK_CLOSED;

    if (len == 0)
      return SOCK_ERROR;

    int ret;
    do {
      ret = mbedtls_ssl_write(&ssl, data,len);

      if(ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
	mbedtls_error(ret,"Failed to write",0);
	disconnect();
	return ret;
      }
    }  while (ret <= 0);
    
    LOG_DEBUG("%d bytes written.\n", ret);

    if(ret!=len)
      LOG_WARN("mbedtls_write %d / %d  bytes written !!!\n", ret,len);
      
    
    return ret;
  }

  bool more_to_come=0;
  virtual bool data_in_buf() const {return more_to_come;}

  virtual int read(unsigned char *data,int maxlen) {
    more_to_come=0;
    if (!connected) return SOCK_CLOSED;
    
    int ret=mbedtls_ssl_read(&ssl, data, maxlen);
    if(ret== MBEDTLS_ERR_SSL_TIMEOUT) {
      LOG_DEBUG("timeout int tls:read\n");
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

    size_t a=mbedtls_ssl_get_bytes_avail(&ssl);
    more_to_come=(a>0);

    return ret;

  }

};

template<unsigned int bfsize=4096>
struct clientbuff_t {
  socket_t *sock=NULL;
  bool end=0;
  int dbg=DBGBASE;

  void log(const char *file,const char *fn,int line,int lvl, const char* format, ... )
  {
    if(lvl>dbg) return;
    va_list arglist;
    
    printf("[%s][clientbuff %p :: %s:%d] ",loglvlstr[lvl],this,fn,line);
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
  }

  cvector_t<unsigned char,bfsize> buffer;
  
  void clear() {
    if(sock)
      sock->disconnect();
    sock=NULL;
    buffer.clear();
    end=0;
  }
  
  
  int read_until(unsigned char *data,int maxlen,const char *m,int ml) {
    int wr=0;
    int pt=0;
    while(wr<maxlen) {
      LOG_DEBUG("RU wr=%d / %d | bf.size=%d\n",wr,maxlen,int(buffer.size()));
      int ret=0;
      if(buffer.size()>0) {
	LOG_DEBUG("RU buffered %d\n",int(buffer.size()));
	assert(wr==0);
	assert(buffer.size()<maxlen);
	ret=buffer.read(data,maxlen);
	if(dbg>_LOG_DEBUG) {
	  printf("in buf: >>>>");
	  for(int i=0;i<ret;i++)
	    printf("%c",data[i]);
	  printf("<<<<\n");
	}
      } else {
	assert(buffer.size()==0);
	ret=0;
	if(!end)
	  ret=sock->read(data+wr, maxlen-wr);
	else {
	  LOG_DEBUG("RU: end !\n");
	}
	if(dbg>_LOG_DEBUG) {
	  printf("sock->read rets %d\n",ret);
	  printf(">>>>");
	  for(int i=0;i<ret;i++)
	    printf("%c",data[wr+i]);
	  printf("<<<<\n");
	}
      }
      
      LOG_DEBUG("RU rcv %d\n",ret);
      
      if(ret<0) {
	LOG_WARN("error read in read_until ret=%d\n",ret);
	return ret;
      }

      if(ret==0) {
	//closed
	end=1;
	return wr;
      }
      
      while(pt+ml<=wr+ret) {
	if(0==strncmp((char*)data+pt,m,ml)) {
	  LOG_DEBUG("RU found pt=%d\n",pt);
	  int wr2=pt+ml;
	  wr+=ret;
	  LOG_DEBUG("RU wr=%d wr2=%d\n",wr,wr2);
	  if(wr2<wr) {
	    assert(buffer.size()==0);
	    buffer.push_back(data+wr2,wr-wr2);
	  }
	  return wr2;
	}
	pt++;
      }

      wr+=ret;
      LOG_DEBUG("RU got %d/%d\n",wr,maxlen);
    }

    //maxlen...
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

string get_ip_2(const string &host,socket_t *sock) {
  clientbuff_t<256> *cb=new clientbuff_t<256>();
  cb->sock=sock;
  
  string url= "/ip";
  string req=httprequest(url,host,1);

  string ip;
  bool ok=0;
  
  if(!sock->write_string(req)) {
    delete cb;
    return "";
  }

  char bf[257];
  //int nl=0;
  int tt=0;

  while(1) {
    int rr=cb->read_until((unsigned char*)bf,256,"\n",1);
    if(rr<=0) break;
    bf[rr]=0;
    //printf("get_ip %s\n",bf);
    tt+=rr;
    bf[rr]=0;
    if(bf[0]=='\r' || bf[0]=='\n') ok=1;

    if(ok) {
      auto x=cut(bf);
      if(x.size())
	ip=x[0];
    }
  }

  //printf("ip: '%s'\n",ip.c_str());

  delete cb;
  return ip;
}

string get_ip(const string &host,socket_t *sock,int port) {
  if(1!=sock->connect(host,port)) return "";
  return get_ip_2(host,sock);
}

string get_public_ip_tls(const string &host,int port) {
  socket_tls_t *sock=new socket_tls_t();
  sock->set_timeout(10*1000+32);
  auto r=get_ip(host,sock,port);
  delete sock;
  return r;
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

string get_public_ip_server() {
  static string c="";
  static long long old=0;
  if(get_unix_time()>old+3600) c.clear();
  if(c.size()) return c;

  old=get_unix_time();
  string r;
  r=get_public_ip_tls("ifconfig.me",443);
  if(r.size() && is_ipv4(r.c_str())) return (c=r);
  r=get_public_ip_tls("ifconfig.co",443);
  if(r.size() && is_ipv4(r.c_str())) return (c=r);
  r=get_public_ip_tls("ifconfig.io",443);
  if(r.size() && is_ipv4(r.c_str())) return (c=r);
  return r;
}


void shitty_http_server(socket_t &sr,string b="<html><body>HELLO WORLD</body></html>\r\n")
{
  char bf[256];
  sr.set_timeout(10000+21); //10 secs
  clientbuff_t<256> cb;
  cb.sock=&sr;
  
  while(1) {
    int rr=cb.read_until((unsigned char*)bf,255,"\n",1);
    //printf("shitty_http_server read_until rets %d\n",rr);
    if(rr==0) break;
    if(rr<0) {
      break;
    }
    bf[rr]=0;
    LOG_INFO("shitty_http_server got '%s\n",bf);
    if(bf[0]=='\r' || bf[0]=='\n') {
      LOG_INFO("shitty_http_server send body\n");
      sr.write((const unsigned char*)b.c_str(),b.size());
      break;
    }
  }
  
  sr.disconnect();
}
			

