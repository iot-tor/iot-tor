#pragma once
#include  <sys/poll.h>

#include <vector>
#include <set>
#include <map>

using namespace std;

void clean_delete_circuit();

enum pollable_cb_type_t {
  POLL_POLLIN=1,
  POLL_POLLOUT=2,
  POLL_TIMEOUT=4,

  POLL_POLLNVAL=8,
  POLL_WAIT=-1, //wait the next pool loop
  POLL_FREE=-2,
};

struct poll_reg_t {
  short events=0;
  short fd=-1;
  int timeout=0; //ms
  int last=0;
#ifdef DBGPOLL
  string name;
#endif

  void print() {
#ifdef DBGPOLL
    printf("'%s' ",name.c_str());
#endif
    printf("e=%d fd=%d to=%d last=%d\n",events,fd,timeout,last);
  }
  void unreg() {
    events=POLL_WAIT;
    fd=-1;
    timeout=last=0;
  }
  void clear() {
    events=POLL_FREE;
  }
  bool isfree() const {
    return events==POLL_FREE;
  }
  bool iswait() const {
    return events==POLL_WAIT;
  }
};


struct pollable_t;

struct poll_chain_t {
  pollable_t *t[4];
  poll_chain_t() {
    clear();
  }
  void push(pollable_t *a) {
    if(t[2]==NULL) t[2]=a;
    else if(t[1]==NULL) t[1]=a;
    else if(t[0]==NULL) t[0]=a;
    else {
      LOG_FATAL("pollchain full\n");
    }
  }
  pollable_t **ptr() {
    if(t[2]==NULL) return t+3;
    if(t[1]==NULL) return t+2;
    if(t[0]==NULL) return t+1;
    return t;
  }

  void pop() {
    if(t[0]) t[0]=NULL;
    else if(t[1]) t[1]=NULL;
    else if(t[2]) t[2]=NULL;
    else {
      LOG_FATAL("pollchain empty\n");
    }
  }

  bool operator==(const poll_chain_t &pc) const {
    return memcmp(t,pc.t,sizeof(t))==0;
  }
  void clear() {
    memset(t,0,sizeof(t));
  }
  bool empty() {
    return t[2]==NULL;
  }

};


struct poller_t {
  virtual void reg(poll_chain_t &pc,poll_reg_t &r)=0;
  virtual void unreg(poll_chain_t &pc)=0;
  
  virtual ~poller_t() {}

};

struct pollable_t {
  poller_t *poller=NULL;
  virtual void pcallback(pollable_t **pc,poll_reg_t &r)=0;// {}

  void reg(poll_reg_t &r)
  {
    LOG_DEBUG("reg fd=%d e=%d\n",r.fd,r.events);
    assert(poller);
    poll_chain_t pc;
    pc.push(this);
    poller->reg(pc,r);
  }

  void unreg() {
    LOG_DEBUG("unreg\n");
    assert(poller);
    poll_chain_t pc;
    pc.push(this);
    poller->unreg(pc);
  }

};



struct union_poller_t : public poller_t, public pollable_t {
  
  virtual void reg(poll_chain_t &pc,poll_reg_t &r)
  {
    LOG_INFOV("union_poller.reg %p %p %p %p %d\n",pc.t[0],pc.t[1],pc.t[2],pc.t[3],r.fd);
    pc.push(this);
    poller->reg(pc,r);
    pc.pop();
  }

  virtual void unreg(poll_chain_t &pc)
  {
    LOG_INFOV("union_poller.unreg %p %p %p %p\n",pc.t[0],pc.t[1],pc.t[2],pc.t[3]);
    pc.push(this);
    poller->unreg(pc);
    pc.pop();
  }

  virtual void pcallback(pollable_t **chain,poll_reg_t &fds) {
    assert(chain[0]);
    chain[0]->pcallback(chain+1,fds);
  }
  
  virtual ~union_poller_t() {}
};


#ifdef LINUX
#define POLLSIZE 64
#else
#define POLLSIZE 32
#endif

struct real_poller_t : public poller_t {
  poll_chain_t pcs[POLLSIZE];
  poll_reg_t fr[POLLSIZE];

  struct pollfd fds[POLLSIZE];
  int nfds=0;

  pthread_t tid;

  int timeout_msecs=200;

  short orig[POLLSIZE];

  mutex_t mut;
  
  void lock() {
    mut.lock();
  }

  void unlock() {
    mut.unlock();
  }

  real_poller_t(bool st=0) {
    //memset(pcs,0,sizeof(pcs));
    //memset(fr,0,sizeof(fr));
    for(int i=0;i<POLLSIZE;i++)
      fr[i].clear();
    if(st)
      start_thread_();      
  }

  void printall() {
    for(int i=0;i<POLLSIZE;i++) {
      poll_chain_t &pc(pcs[i]);
      poll_reg_t &pr(fr[i]);
      printf("%2d: %p %p %p %p ",i, pc.t[0],pc.t[1],pc.t[2],pc.t[3]);
      pr.print();
    }
  }
  
  virtual void reg(poll_chain_t &pc,poll_reg_t &r) {
    LOG_INFOV("npoller.reg %p %p %p %p %d\n",pc.t[0],pc.t[1],pc.t[2],pc.t[3],r.fd);
    r.last=timer_get_ms();
    start_thread_();
    if(main_dbg>=_LOG_DEBUGVV) printall();

    for(int i=0;i<POLLSIZE;i++)
      if(pc==pcs[i]) {
	fr[i]=r;
	LOG_INFOV("pc reg find at i=%d\n",i);
	if(main_dbg>=_LOG_DEBUGV) printall();
	return;
      }
    for(int i=0;i<POLLSIZE;i++)
      if(fr[i].isfree()) {
	fr[i]=r;
	pcs[i]=pc;
	LOG_INFOV("pc new at i=%d\n",i);
	if(main_dbg>=_LOG_DEBUGVV) printall();
	return;
      }
    printall();
    LOG_FATAL("poller full. change POLLSIZE\n");
  }

  virtual void unreg(poll_chain_t &pc) {
    LOG_INFOV("npoller.unreg %p %p %p %p\n",pc.t[0],pc.t[1],pc.t[2],pc.t[3]);
    if(main_dbg>=_LOG_DEBUGVV) printall();
    for(int i=0;i<POLLSIZE;i++)
      if(pc==pcs[i]) {
	pcs[i].clear();
	fr[i].unreg();
	LOG_INFOV("pc unreg find at i=%d\n",i);
	if(main_dbg>=_LOG_DEBUGVV) printall();
	return;
      }
    LOG_SEVERE("pc not reg\n");
  }

  volatile bool exit=0;
  void stop() {
    exit=1;
  }
  
  void th() {
    mut.lock();
    mut.unlock();
    for(int pass=1;!exit;pass++) {
      clean_delete_circuit();

      int k=0;
      memset(fds,0,sizeof(fds));

      //construct real_fds
      for(int i=0;i<POLLSIZE;i++) {
	if(fr[i].iswait())
	  fr[i].clear();
	if(pcs[i].empty()) continue;

#ifdef DBGPOLL
	LOG_DEBUG("create poll [%d] %p %p %p %p k=%d i=%d fd=%d e=%d to=%d last=%d '%s'\n",pass,pcs[i].t[0],pcs[i].t[1],pcs[i].t[2],pcs[i].t[3],k,i,fr[i].fd,fr[i].events,fr[i].timeout,fr[i].last,fr[i].name.c_str());
#else
	LOG_DEBUG("create poll [%d] %p %p %p %p k=%d i=%d fd=%d e=%d to=%d last=%d\n",pass,pcs[i].t[0],pcs[i].t[1],pcs[i].t[2],pcs[i].t[3],k,i,fr[i].fd,fr[i].events,fr[i].timeout,fr[i].last);
#endif

	if((fr[i].events&POLL_POLLNVAL)==0) {
	  if(fr[i].events&POLL_POLLIN||fr[i].events&POLL_POLLOUT) {
	    fds[k].fd=fr[i].fd;
	    if(fr[i].events&POLL_POLLOUT)
	      fds[k].events=POLLOUT;
	    if(fr[i].events&POLL_POLLIN)
	      fds[k].events=POLLIN;
	    LOG_DEBUG("add poll k=%d i=%d fd=%d e=%d\n",k,i,fr[i].fd,fr[i].events);
	    orig[k]=i;
	    k++;
	  }
	}
      }

      nfds=k;
      LOG_DEBUGV("poller poll k=%d ...\n",k);
      int ret = poll(fds, k, timeout_msecs);
      LOG_DEBUGV("poller poll k=%d ret=%d\n",k,ret);
      int now=timer_get_ms();

      for(int i=0;i<POLLSIZE;i++) {
	if(pcs[i].empty()) continue;
	if(fr[i].events&POLL_TIMEOUT) {
	  if(fr[i].last<=0) {
	    LOG_INFO("warn fr[i].last<=0\n");
	    fr[i].last=now;
	  }
	  if((now-fr[i].last)>=fr[i].timeout) { 
            int o=fr[i].last;
	    fr[i].last=now;
	    auto p=pcs[i].ptr();
	    assert(p && p[0]);
	    poll_reg_t r;
	    r.events=0;
	    r.fd=fr[i].fd;
	    r.events=POLL_TIMEOUT;
	    r.timeout=(now-o);
	    p[0]->pcallback(p+1,r);
	  }
	}
      }


      for(int i=0;i<nfds;i++) {
	int ii=orig[i];
	int e=fds[i].revents;
	LOG_DEBUGV("poll result i=%d (orig=%d) re=%d\n",i,ii,e);
	if(pcs[ii].empty()) {
	  LOG_DEBUGV(" skip pcs[ii].empty())\n");
	  continue;
	}
	//TODO maks event with fr[ii].events ?
	if ((e & POLLIN) || (e & POLLOUT)) {
	  LOG_DEBUGV("poller callback POLL IN/OUT i=%d fd=%d \n",i,fds[i].fd);
	  fr[ii].last=now;
	  assert(!pcs[ii].empty());
	  auto p=pcs[ii].ptr();
	  assert(p && p[0]);
	  poll_reg_t r;
	  r.fd=fds[i].fd;
	  r.events=0;
	  if(fds[i].revents & POLLIN)
	    r.events|=POLL_POLLIN;
	  if(fds[i].revents & POLLOUT)
	    r.events|=POLL_POLLOUT;
	  LOG_DEBUGV("poller callback POLL IN/OUT i=%d fd=%d e=%d\n",i,r.fd,r.events);
	  p[0]->pcallback(p+1,r);
	}
	if((e&POLLNVAL)) {
	  LOG_WARN("poller POLLNVAL i=%d fd=%d \n",i,fds[i].fd);
	  fr[ii].events|=POLL_POLLNVAL;
	}
      }

    }
  }

  static void *sth(void *a)
  {
#ifdef INSTR
    char bbb=0;
    char*p=(char*)&bbb;
    instr_base=p;
    printf("XXXXXX %p\n",p);
#endif
    real_poller_t *aa=(real_poller_t*)a;
    aa->th();
    return NULL;
  }

  bool launched=0;
  void start_thread_() {
    if(launched==0) {
      launched=1;
      LOG_INFOV("launch poller thread \n");
#if 1 // for ESP: this is the main thread, so give it a lot of stack
      pthread_attr_t attr;
      int r=pthread_attr_init(&attr);
      assert(r==0);
      size_t s;
      r=pthread_attr_getstacksize(&attr,&s);
      assert(r==0);
      LOG_INFOV("default stack size: %d\n",int(s));
      if(s<8192) {
	s=8192;
	LOG_INFOV("set stack size to %d\n",int(s));
	r=pthread_attr_setstacksize(&attr,s);
	assert(r==0);
      }
#endif
      r=pthread_create(&tid,&attr,sth,this);

      if(r)
	LOG_FATAL("pthread_create fails r=%d\n",r);
      pthread_attr_destroy(&attr);
#ifdef INSTR
      //instr_watch=tid;
#endif
    }
  }
};

real_poller_t main_poller;

