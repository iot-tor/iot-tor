struct s_t {
  virtual void push(const unsigned char *in, int inlen) { //default: identity 
    proc(in,inlen);
  }

  void set_sink(s_t &x) {sink=&x;}
  s_t(s_t &x) {sink=&x;}
  s_t() {sink=NULL;}
  
  void printf(const char *format, ... )
  {
    va_list args;
    char buffer[512];
    va_start (args, format);
    vsnprintf (buffer,256,format, args);
    va_end (args);
    push((unsigned char*)buffer,strlen(buffer));
  }

  virtual void start() {}
  virtual void finish() {}

  void proc(const unsigned char *bf, int len) {
    sink->push(bf,len);
  }

  s_t *sink=NULL;
  
  virtual ~s_t() {}
};

struct s_aes_t : public s_t {
  mbedtls_cipher_context_t *cipher_ctx;
  unsigned char key[32];
  unsigned char iv[16];

  s_aes_t(s_t &a):s_t(a) {}
  s_aes_t() {}
  
  void push(const unsigned char *in,int inlen) {
    unsigned char out[inlen];
    size_t olen;
    //proc(in,inlen);    return;
    int r=mbedtls_cipher_update( cipher_ctx, in, inlen, out, &olen );
    assert(r==0 && olen==inlen);
    proc(out,olen);
  }
};

struct s_pem_t : public s_t {
  string name;
  s_pem_t(const string &m,s_t &b):s_t(b) {name=m;}
  s_pem_t() {}
  void init(const string &m,s_t &b) {
    name=m;
    set_sink(b);
  }
  
  void start() {
    sink->printf("-----BEGIN %s-----\n",name.c_str());
  }
  
  unsigned char b[50];
  int p=0;

  void finish() {
    char tmp[65];
    size_t ol;
    if(p) {
      int r=mbedtls_base64_encode((unsigned char *)tmp,64,&ol,b,p);
      assert(r==0);
      tmp[ol]=0;
      sink->printf("%s\n",tmp);
    }
    sink->printf("-----END %s-----\n",name.c_str());
  }

  void pushb(const unsigned char *b) {
    char tmp[68];
    size_t ol;
    int r=mbedtls_base64_encode((unsigned char*)tmp,66,&ol,b,48);
    assert(r==0 && ol==64);
    tmp[ol]=0;
    sink->printf("%s\n",tmp);
  }

  void push(const unsigned char *in,int inlen) {
    while(p+inlen>=48) {
      if(p) {
	int n=48-p;
	memcpy(b+p,in,n);
	pushb(b);
	inlen-=n;in+=n;
	p=0;
      } else {
	pushb(in);
	in+=48;
	inlen-=48;
	p=0;
      }
    }
    if(inlen) {
      memcpy(b+p,in,inlen);
      p+=inlen;
      assert(p<48);
    }
  }
};


struct s_sign_t : public s_t {
  vector<unsigned char> message;
  bool body;
  
  s_sign_t(s_t &a):s_t(a) {}
  s_sign_t() {}

  void start_md() {body=1;}
  void stop_md() {body=0;}
  void update_md(const unsigned char *bf,int len) {
    append(message,bf,len);
  }

  void push(const unsigned char *in, int inlen) {
    if(body)
      update_md(in,inlen);
    proc(in,inlen);
  }
};

void pem(const char *name,unsigned char *bf,int l,s_t &a)
{
  a.printf("-----BEGIN %s-----\n",name);
  char tmp[68];
  while(l>48) {
    size_t ol;
    int r=mbedtls_base64_encode((unsigned char*)tmp,66,&ol,bf,48);
    //printf("r=%d ol=%d len=%d\n",r,int(ol),strlen(tmp));
    assert(r==0 && ol==64);
    tmp[ol]=0;
    a.printf("%s\n",tmp);
    l-=48;
    bf+=48;
  }
  size_t ol;
  int r=mbedtls_base64_encode((unsigned char*)tmp,64,&ol,bf,l);
  assert(r==0);
  tmp[ol]=0;
  a.printf("%s\n",tmp);
  a.printf("-----END %s-----\n",name);
}


struct s_f_t : public s_t {
  FILE *out=NULL;
  s_f_t(const char *fn="test_s"):s_t() {
    out=fopen(fn,"w");
  }
  void push(const unsigned char *in,int inlen) {
    fwrite(in,1,inlen,out);
  }
  void finish() {
    fclose(out);
  }
};

struct s_vc_t : public s_t {
  ps_vector<char> &vc;
  s_vc_t(ps_vector<char> &v):s_t(),vc(v) {
  }
  void push(const unsigned char *in,int inlen) {
    int r=vc.size();
    if(r+inlen>vc.maxsize()) return;
    vc.resize(r+inlen);
    memcpy(vc.data()+r,in,inlen);
  }
  void finish() {
  }
};


struct s_out_t : public s_t {
  s_out_t():s_t() {  }
  void push(const unsigned char *in,int inlen) {
    fwrite(in,1,inlen,stdout);
  }
  void finish() {
  }
};
