int tor_dbg=DBGBASE;
#include "circuit.hpp"
#include "dir.hpp"

int tor_refresh_interval=TOR_REFRESH_TIME;
int tor_first_refresh=0;
int tor_nb_refresh=0;
bool tor_hsdirs_ok=0;
long long last_save_cache=0;

bool tor_refresh_cons(int refresh)
{
  //printf("relays.time = %Ld (%Ld s back) refresh=%d\n",relays.time,get_unix_time() - relays.time,refresh);

  if(refresh==0) {
    if(get_unix_time() - relays.time > tor_refresh_interval) {
      refresh=2;
    }
    else return 1;
  }

  LOG_INFO("tor_refresh %d\n",refresh);

  int nb=count_flags(info_node_t::FL_DIFF);
  int nbc=count_flags(info_node_t::FL_CONS);
  LOG_INFOV("%d diff %d cons\n",nb,nbc);
  
  float refrest_percent=0;
  if(refresh==1) refrest_percent=0.;
  if(refresh==2) refrest_percent=0.2;
  if(refresh>=3) refrest_percent=1.;
  
  //get_tp();

#ifdef LINUX
  if(tor_dbg>2)
    cache_printtab();
#endif
  
  // refresh_consensus
  consensus_t *r=new consensus_t;
  LOG_INFO("download consensus...\n");

  consdown_t *c=new consdown_t(*r);

  tor_hsdirs_ok=0;
  
  int to=10*ESP_TO_FACT;
  for(int p=0;;p++) {
    LOG_INFOV("timeout set to: %d s\n",to);
    ip_info_node_t a;
    select_one_dir(a);
    c->clear();
    clear_cons_flag();

    int nb=count_flags(info_node_t::FL_DIFF);
    int nbc=count_flags(info_node_t::FL_CONS);
    LOG_INFOV("%d diff %d cons\n",nb,nbc);
  
    // if(tor_dbg>4) {
    //   printf("after clear cache flags\n");
    //   cache_printtab();
    // }
    r->clear_auths();
    r->nblines=relays.nblines;
    
    if(c->download_consensus_z(a,to*1000))
      break;
    to*=1.5;
    if(to>1000) to=1000;
    if(p>40) {
      LOG_WARN("bootstrap failed...\n");
      sleep(60);
      //reset
    }

  }

  // if(tor_dbg>4) {
  //   printf("after dl cons\n");
  //   cache_printtab();
  // }

  // if(tor_dbg>2) {
  //   r->print();
  //   c->print_stats();
  // }

  if(refresh<=2 && !c->check_auth_list(relays))
    goto inittor_fail;

  //TODO fill c->relays with relays
    
  if(!download_auth_descriptors(c->relays))
    goto inittor_fail;

  if(!c->check_consensus_sigs())
    goto inittor_fail;

  LOG_INFO("download consensus ok\n");
  r->del_dir_keys();
  c->copy_est();
  

  // if(tor_dbg>5) {
  //   printf("=== BEFORE CLEAN ====\n");
  //   relays.printtab();
  // }
  relays.clean();
  // if(tor_dbg>5) {
  //   printf("=== AFTER  CLEAN ====\n");
  //   //relays.printtab();
  //   printf("refresh %f percents...\n",refrest_percent);
  // }
  relays.refresh(*r,refrest_percent);
  relays.write_file(BASEPATH CONSFILE);

  delete c;
  delete r;


  // if(tor_dbg>3) {
  //   cache_printtab();
  //   relays.printtab();
  // }
  
  return 1;
  
 inittor_fail:
  return false;
}

bool tor_refresh_descs()
{
  LOG_INFOV("tor_refresh_descs\n");

#ifndef DISABLE_CACHE
  //download_all_descriptors(6.);  // force refresh of all hsdir without id25519
  download_all_descriptors(0.);  // 1.:force refresh for nodes >=6 days
#endif
  tor_hsdirs_ok=1;
  
  if(get_unix_time()-last_save_cache>TOR_SAVE_TIME || force_save_cache()) {
    relays.write_file(BASEPATH CONSFILE);
    save_diff_cache();
    last_save_cache=get_unix_time();
  } 
    
  // if(tor_dbg>2)
  //   cache_printtab();
//   if(tor_dbg>2) {
//     printf("=== AFTER DW ALL DESC ===\n");
//     cache_printtab();
//     //relays.printtab();
// #ifdef DIR_LOWMEM
//     if(exit_port) {
//       int pok=0;
//       for(int j=0;j<MAX_NODES;j++) {
// 	if(relays.nodes[2][j].flags&info_relay_t::FL_PORT_OK) pok++;
//       }
//       printf("exit port ok : #%d\n",pok);
//     }
// #endif
//   }
  
  return 1;
  
}


bool tor_init_() {  
  random_generator_init();

#ifndef DISABLE_CACHE
  cache_descs=PSRAM_NEW<info_node_t>(CACHE_SIZE);
  read_cache();
  //cache_printtab();
#endif
  
  if(!relays.read_file(BASEPATH CONSFILE)) {
    LOG_INFO("CONSFILE not present: refresh all\n");
    tor_first_refresh=10;
  }

  int nb=count_flags(info_node_t::FL_DIFF);
  int nbc=count_flags(info_node_t::FL_CONS);
  LOG_INFOV("%d diff %d cons\n",nb,nbc);
  
  return 1;
}

void *th_tor(void *) {
  bool r=tor_init_();
  assert(r);
  
  while(1) {
    mutex_dir.lock();
    while(1) {
      int r=tor_refresh_cons(tor_first_refresh);
      if(r) break;
      LOG_WARN("tor_refresh fails...\n");
      sleep(1);
    }
    
    tor_refresh_descs();

    mutex_dir.unlock();
    
    LOG_INFO("Tor refresh finished\n");
    tor_nb_refresh++;
    tor_first_refresh=0;
    sleep(TOR_REFRESH_LOOP_TIME);
  }
}

pthread_t thidtor;

bool tor_init() {  
  LOG_INFO("create thread for Tor init/refresh.\n");
  int r=pthread_create(&thidtor,NULL,th_tor,NULL);
  if(r)
    LOG_SEVERE("pthread_create fails tor_init r=%d\n",r);

  bool first=0;
#ifdef DIR_LOWMEM
  first=(tor_first_refresh>=10);
#endif
  first=1;
  for(int i=0;i<1800;i++) { //wait first refresh
    if(first==1) {
      if(tor_nb_refresh) return 1;
    } else {
      if(tor_hsdirs_ok) {
	return 1;
      }
    }
    sleep(1);
  }
  assert(0);
  return 0;
}
  


