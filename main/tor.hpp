/* tor_t is a class which download the consensus and all unkonwn descriptors every TOR_REFRESH_TIME seconds.
   Sequence:
   - download the consensus
   - download the descriptors of auths
   - check the auth signatures of the consensus (and chech that the list of auths does not change too much)
   - for all unknown descriptors of relays in the consensus, download the descriptor.

   If there is a 404 error for a desciptor (there are many such errors, maybe the propagation is not yet finished), it retry one time with an other dir
*/

int tor_dbg=DBGBASE;
#include "dir.hpp"

int tor_first_refresh=10;
long long last_save_cache=0;

#define DL_BUNCH 32


bool tor_init_() {  
  random_generator_init();

#ifndef DISABLE_CACHE
  cache_descs=PSRAM_NEW<info_node_t>(CACHE_SIZE);
  read_cache();
  //cache_printtab();
#endif
  
  if(!relays.read_file(BASEPATH CONSFILE)) {
    LOG_INFO("CONSFILE not present: refresh all\n");
  }

#ifndef DISABLE_CACHE

  int nb=count_flags(info_node_t::FL_DIFF);
  int nbc=count_flags(info_node_t::FL_CONS);
  LOG_INFOV("%d diff %d cons\n",nb,nbc);
#endif
  
  return 1;
}


struct tor_t : public union_poller_t {
  consensus_t *r=NULL;
  consdownproc_t *cp=NULL;
  down_async_z_t *down=NULL;
  multidescproc_t *mdd=NULL;
  set<info_node_t*> sn;
  set_dir_t sd;
  set_dir_t::dir_stat_t *dir=NULL;
  float refrest_percent=0;
  int to=10*ESP_TO_FACT;
  list<set<info_node_t*>> lnodes,lnodes404; //TODO too many ram ?

  short httpcode=0;
  short refresh=-1;
  short nb_refresh=0;

  char fail=0;
  char st=ST_DL_CONS;
  char pass=0; //two passes for dl descs: the second one is a retry for 404 errors

  
  enum status_update_tor_t {
    ST_KO,
    ST_OK,

    ST_DL_CONS,
    ST_DL_CONS_W,
    ST_DL_AUTH,
    ST_DL_AUTH_W,
    ST_DL_DESC,
    ST_DL_DESC_W,
    ST_DL_DESC_C,

    ST_DL_DONE,
  };

  tor_t() {  }
  ~tor_t() {clean();}

  void start() {
    if(refresh<0) refresh=tor_first_refresh;
    poller=&main_poller;
    settimeout(500);
  }

  void settimeout(int to)
  {
    poll_reg_t r;
    r.events=POLL_TIMEOUT;
    r.timeout=to;
#ifdef DBGPOLL
    r.name="tor";
#endif
    union_poller_t::pollable_t::reg(r);
  }

  virtual void pcallback(pollable_t **chain,poll_reg_t &fds) {
    if(chain[0]==NULL) {
      assert(fds.events==POLL_TIMEOUT);
      if(st==ST_DL_CONS || st==ST_OK|| st==ST_KO)
	while(loop());
      return;
    }
    union_poller_t::pcallback(chain,fds);
    if(down && (down->done<0 || down->done==4)) {
      while(loop());
    }
  }

  int refresh_consensus() {
    LOG_INFO("tor_refresh %d\n",refresh);

#ifndef DISABLE_CACHE
    int nb=count_flags(info_node_t::FL_DIFF);
    int nbc=count_flags(info_node_t::FL_CONS);
    LOG_INFOV("%d diff %d cons\n",nb,nbc);
#endif
  
    if(refresh==1) refrest_percent=0.;
    if(refresh==2) refrest_percent=0.2;
    if(refresh>=3) refrest_percent=1.;
  
    // refresh_consensus
    assert(r==NULL);
    r=new consensus_t;

    assert(cp==NULL);
    cp=new consdownproc_t(*r);

    return start_download_consensus();
  }

  int start_download_consensus() {
    LOG_INFO("download consensus...\n");
  
    //tor_hsdirs_ok=0;
  
    LOG_INFOV("timeout set to: %d s\n",to);


    dir=sd.select_one_dir();
    assert(dir);

    cp->clear();
    clear_cons_flag();

    assert(down==NULL);
    down=new down_async_z_t(*this);
    down->proc=cp;

    r->clear_auths();
    r->nblines=relays.nblines;

    return down->download("/tor/status-vote/current/consensus.z",*dir,to*1000);
  }

  int check_dl_consensus() {
    // -1: still working
    //  0: fail
    //  1: ok
    if(down->done>=0 &&down->done<4) {
      LOG_INFO("wait cons down done=%d nl=%d...\n",down->done,down->nl);
      return -1;
    }

    int st=down->done;
    LOG_INFO("cons down done=%d...\n",st);

    if(st!=4 || (refresh<=2 && !cp->check_auth_list(relays)) ) {
      sd.mark(*dir,0);
      
      to*=1.5;
      if(to>1000) to=1000;
      
      clean();
      
      return 0;
    }
    
    assert(down);
    delete down;
    down=NULL;

    sd.mark(*dir,1,1000);

    return 1;
  }


  int dl_auths() {
    sn.clear();
    for(int j=0;j<MAX_NODES_AUTH;j++) {
      if(cp->relays.nodes_auth[j].is_ok()==false) continue;
      sn.insert(&(cp->relays.nodes_auth[j]));
    }

    assert(mdd==NULL);
    mdd=new multidescproc_t;
    mdd->relays=&(cp->relays);

    assert(down==NULL);
    down=new down_async_z_t(*this);
    down->proc=mdd;

    dir=sd.select_one_dir();
    assert(dir);

    mdd->init_req(sn,1,1000*10);
    
    return down->download(mdd->path,*dir,1000*10);
  }

  
  int check_dl_descs() {
    // -1: still working
    //  0: fail
    //  1: ok
    if(down->done>=0 &&down->done<4) {
      LOG_WARN("wait dl descs done=%d nl=%d...\n",down->done,down->nl);
      return -1;
    }

    int st=down->done;
    LOG_INFO("dl descs done=%d... httpcode=%d\n",st,mdd->httpcode);

    if(st!=4) {
      if(mdd->httpcode!=404) {
	sd.mark(*dir,0);
      } else {
	sd.mark(*dir,404);
      }
    } else {
      sd.mark(*dir,1,mdd->totaltime());
    }
    httpcode=mdd->httpcode;

    assert(down);
    delete down;
    down=NULL;
    assert(mdd);
    delete mdd;
    mdd=NULL;

    return st==4;
  }
    

  int validate_cons() {
    int ret=0;
    if(!cp->check_consensus_sigs()) {
      LOG_WARN("consensus sig fail\n");
    } else {
      LOG_INFO("download consensus ok\n");

      mutex_dir.lock();
      ncons_to_cons_flag();
      mutex_dir.unlock();
  

      r->del_dir_keys();
      cp->copy_est();

      relays.clean();
      relays.refresh(*r,refrest_percent);
      relays.write_file(BASEPATH CONSFILE);

      ret=1;
    }

    clean();

    return ret;
  }

  int dl_desc() {
    assert(mdd==NULL);
    mdd=new multidescproc_t;
    mdd->relays=&relays;

    assert(down==NULL);
    down=new down_async_z_t(*this);
    down->proc=mdd;

    auto n=lnodes.front();

    mdd->init_req(n,0,10*1000);

    dir=sd.select_one_dir();
    assert(dir);

    return down->download(mdd->path,*dir,1000*10);
  }


  int make_lnodes(float tg=0.) {
    lnodes.clear();
    lnodes404.clear();
    int change=0;
    
    set<info_node_t*> nodes;
#ifdef DIR_LOWMEM
    for(int i=0;i<NODETYPES;i++)
      for(int j=0;j<MAX_NODES;j++) {
	if(relays.nodes[i][j].is_ok()==false) {
	  relays.nodes[i][j].kill();
	  continue;
	}
	LOG_INFOV("download descriptor %d %d\n",i,j);
	if(relays.nodes[i][j].need_refresh_rand(tg)==false) {
	  LOG_INFO("no need to refresh it\n");
	  continue;
	}
	nodes.insert(&relays.nodes[i][j]);
	change++;
	if(nodes.size()>=DL_BUNCH) {
	  lnodes.push_back(nodes);
	  //download_descriptors(nodes,sd);
	  nodes.clear();
	}
      }
#endif
  
#ifndef DISABLE_CACHE
    for(int it=0;it<CACHE_SIZE;it++) {
      if(cache_descs[it].flags&info_node_t::FL_CONS) {
	if(cache_descs[it].is_ok()==false) {
	  cache_descs[it].kill();
	}
      }

      if(cache_descs[it].need_refresh_rand(tg)) {
	nodes.insert(&cache_descs[it]);
	change++;
	if(nodes.size()>DL_BUNCH) {
	  lnodes.push_back(nodes);
	  //download_descriptors(nodes,sd);
	  nodes.clear();
	}
      }
    }
#endif
    if(nodes.size()>0) {
      lnodes.push_back(nodes);
      //download_descriptors(nodes,sd);
      nodes.clear();
    }
    return change;
  }

  void clean() {
    if(down) {
      delete down;
      down=NULL;
    }
    if(mdd) {
      delete mdd;
      mdd=NULL;
    }
    if(cp) {
      delete cp;
      cp=NULL;
    }
    if(r) {
      delete r;
      r=NULL;
    }
  }

  bool failst(int x,int d=1,int m=5)
  {
    fail+=d;
    if(fail>=m) {
      LOG_WARN("too many fails...\n");
      st=ST_KO;
      clean();
      return 1;
    }
    st=x;
    return 0;
  }

  bool loop() {
    LOG_DEBUG("tor loop st=%d\n",st);
    if(st==ST_DL_DONE) {
      LOG_INFO("Tor update done\n");
      if(get_unix_time()-last_save_cache>TOR_SAVE_TIME || force_save_cache()) {
	LOG_INFO("save descriptors\n");
	relays.write_file(BASEPATH CONSFILE);
	save_diff_cache();
	last_save_cache=get_unix_time();
      } 
      nb_refresh++;
      st=ST_OK;
      settimeout(60*1000);
      return 1;
    }
    if(st==ST_OK) {
      if(get_unix_time() - relays.time > TOR_REFRESH_TIME) {
	LOG_INFO("refresh since now=%d - relays.time=%d > TOR_REFRESH_TIME=%d\n",get_unix_time(),relays.time, TOR_REFRESH_TIME);
	st=ST_DL_CONS;
	return 1;
      }

      return 0;
    }
    if(st==ST_KO) {
      if(get_unix_time() - relays.time > TOR_REFRESH_TIME_WHEN_FAILS) {
	st=ST_DL_CONS;
	return 1;
      }
      return 0;
    }
    
    if(st==ST_DL_CONS) {
      pass=0;
      sd.init();
      refresh_consensus();
      st=ST_DL_CONS_W;
      return 0;
    }
    
    if(st==ST_DL_CONS_W) {
      int r=check_dl_consensus();
      if(r==0) {
	LOG_WARN("fail dl cons\n");

	clean();

	failst(ST_DL_CONS);
	return 1;
      }
      if(r==1) {
       	fail=0;
	st=ST_DL_AUTH;
	return 1;
      }
      LOG_WARN("CHECK DL CONS = %d\n",r);
      return 0;
    }

    if(st==ST_DL_AUTH) {
      dl_auths();
      st=ST_DL_AUTH_W;
      return 0;
    }
      
    if(st==ST_DL_AUTH_W) {
      int ret=check_dl_descs();
      if(ret==0) {
	LOG_WARN("fail dl auth\n");
	failst(ST_DL_AUTH,0,8);
	return 1;
      }
      if(ret==1) {
	if(!validate_cons()) {
	  failst(ST_DL_CONS);
	  return 1;
	} else {
	  fail=0;
	  st=ST_DL_DESC;
	  return 1;
	}
      }
      LOG_WARN("CHECK DL AUTHS = %d\n",r);
      return 0;
    }

    if(st==ST_DL_DESC) {
      if(sd.bad) sd.init(); //if sd.bad, the list of dir is the static list of auths...
      make_lnodes();
      st=ST_DL_DESC_C;
      return 1;
    }

    if(st==ST_DL_DESC_C) {
      if(lnodes.empty()) {
	if(pass==0) {
	  pass=1;
	  lnodes.swap(lnodes404);
	}
      }

      if(lnodes.empty()) {
	refresh=3;
	st=ST_DL_DONE;
	return 1;
      } else {
	dl_desc();
	st=ST_DL_DESC_W;
	return 0;
      }
    }

    if(st==ST_DL_DESC_W) {
      int r=check_dl_descs();
      if(r==0) {
	LOG_WARN("fail dl descs\n");

	auto x=lnodes.front(); //rotate...
	lnodes.pop_front();
	if(httpcode!=404) {
	  lnodes.push_back(x);
	  failst(ST_DL_DESC_C,1,15);
	} else {
	  if(pass==0) 
	    lnodes404.push_back(x);
	  failst(ST_DL_DESC_C,0,15);
	}
	
	return 1;
      }
      if(r==1) {
	lnodes.pop_front();
	fail=0;
	st=ST_DL_DESC_C;
	return 1;
      }
      LOG_WARN("CHECK DL DESCS = %d\n",r);
      return 0;
    }

    never_here();
  }

  bool in_operation() const {
    if(st!=ST_OK && st!=ST_KO) return 1;
    return 0;
  }

  bool is_ok() const {
    return (st==ST_OK);
  }
  
};

tor_t *tor=NULL;

bool tor_is_ok() {
  if(tor==NULL) return NULL;
  return tor->is_ok();
}

int tor_nb_refresh() {
  if(tor==NULL) return 0;
  return tor->nb_refresh;
}

bool tor_init() {  
  int r=tor_init_();
  assert(r);

  tor=new tor_t;
  tor->start();
  
  for(int i=0;i<1800;i++) { //wait first refresh
    sleep(1);
    if(tor->nb_refresh) {
      assert(has_my_ip());
      return 1;
    }
  }

  return 0;
}
