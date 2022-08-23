#pragma once

struct pollable_t {
  enum pollable_cb_type_t {
    CB_POLLIN,
    CB_BUF,
    CB_TIMEOUT,
  };
  
  int mpass=0;
  int timelimit;
  virtual vector<int> getfds() { return vector<int>();}
  //virtual int gettimeout() {return -1;}

  virtual bool data_in_buf() {return 0;}
  virtual void wcallback(pollable_cb_type_t, int arg=-1) {}
};

void clean_delete_circuit();

struct poller_t {
  poller_t(bool st=0)
  {
    if(st)
      start_thread();      
  }

  vector<pollable_t*> mm;
  mutex_t mut;
  struct pollable_t* b[32];
  struct pollfd fds[32];
  int nfds=0;
  pthread_t tid;
  
  void reg(pollable_t &a) {
    mut.lock();
    for(int i=0;i<mm.size();i++)
      if(mm[i]==NULL) {
	mm[i]=&a;
	mut.unlock();
	return;
      }
    mm.push_back(&a);
    mut.unlock();
  }

  void unreg(pollable_t &a) {
    mut.lock();
    for(int i=0;i<nfds;i++) {
      if(b[i]==&a)
	b[i]=0;
    }
    for(int i=0;i<mm.size();i++)
      if(mm[i]==&a)
	mm[i]=NULL;
    mut.unlock();
  }
  
  void th() {
    int timeout_msecs = 200;
    for(int pass=1;;pass++) {
      clean_delete_circuit();

      mut.lock();
      int k=0;
      memset(fds,0,sizeof(fds));

      LOG_DEBUGV("poller: poll: \n");
      for(int i=0;i<mm.size();i++) {
	auto it=mm[i];
	if(!it) continue;
	auto vfds=it->getfds();
	
	LOG_DEBUGV("poller: poll i=%d it=%p \n",i,it);
	for(auto &fd:vfds) {
	  LOG_DEBUGV("poller: poll (#%d) %p fd=%d\n",k,it,fd);
	  assert(k<sizeof(fds)/sizeof(fds[0])); 
	  fds[k].fd=fd;
	  fds[k].events = POLLIN;
	  b[k]=it;
	  k++;
	}
      }
      nfds=k;
      mut.unlock();

      int ret = poll(fds, k, timeout_msecs);
      LOG_DEBUGV("poller poll ret=%d\n",ret);

      mut.lock();
      

      for(int i=0;i<mm.size();i++) {
	if(mm[i]) {
	  auto it=mm[i];
	  if(it->mpass==0) it->mpass=pass;
	  if(it->timelimit && (pass-it->mpass)*timeout_msecs>=it->timelimit) { // 2 secs
	    it->mpass=pass;
	    mut.unlock();
	    it->wcallback(pollable_t::CB_TIMEOUT,(pass-it->mpass)*timeout_msecs);
	    it=NULL;
	    mut.lock();
	  }
	}
      }

      for(int i=0;i<nfds;i++) {
	if(b[i]==NULL) continue;
	if (fds[i].revents & POLLIN) {
	  LOG_DEBUGV("poller callback POLLIN %p i=%d fd=%d \n",b[i],i,fds[i].fd);
	  b[i]->mpass=pass;
	  mut.unlock();
	  b[i]->wcallback(pollable_t::CB_POLLIN,fds[i].fd);
	  mut.lock();
	  while(b[i] && (b[i]->data_in_buf())) {
	    mut.unlock();
	    b[i]->wcallback(pollable_t::CB_BUF);
	    mut.lock();
	  }
	}
      }

      mut.unlock();
    }
  }

  static void *sth(void *a)
  {
    poller_t *aa=(poller_t*)a;
    aa->th();
    return NULL;
  }

  bool launched=0;
  void start_thread() {
    mut.lock();
    if(launched==0) {
      launched=1;
      LOG_INFOVV("launch th_read_cells_mutu\n");
      int r=pthread_create(&tid,NULL,sth,this);
      if(r)
	LOG_FATAL("pthread_create fails in socketcell::launch_th r=%d\n",r);
    }
    mut.unlock();
  }
  
  

};






