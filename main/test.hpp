
struct test_t {
  int tt=0;
  vector<unsigned char> cc;
  pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;

  void test_cb(const unsigned char *d,int l) {
    if(d==NULL) {
      LOG_INFO("special l=%d\n",l);
      return;
    }

    // printf("CB %d\n",l);
    // for(int i=0;i<l;i++)
    //     printf("%c",d[i]);
    // printf("\n");

    tt+=l;
    pthread_mutex_lock(&m);
    if(cc.size()<l) {
      assert(0);
    }
    for(int i=0;i<l;i++)
      assert(cc[i]==d[i]);

    memmove(cc.data(),cc.data()+l,cc.size()-l);
    cc.resize(cc.size()-l);
    pthread_mutex_unlock(&m);
  }
};

void test(circuit_t *tc,string host,int port)
{
  test_t cc;

  LOG_INFO("tor test() starts\n");
  
  if(!host.empty() && !is_ipv4_address(host)) {
    tc->stream_resolve(host);
  }
  
  LOG_INFO("tor test() resolve done\n");
  
  int id;
  id=tc->stream_start(host,port,std::bind(&test_t::test_cb,&cc,std::placeholders::_1,std::placeholders::_2));

  printf("====== stream_start rets  with id=%d\n",id);
  if(id==0) {
    printf("stream_id==0 : exiting 1\n");
    exit(1);
    return ;
  }


  while(tc->streams[id].connected==false) {
    if(tc->streams[id].finished) break;
    usleep(100000);
  }

  int tt=0;
  for(int p=0;;p++) {
    //printf("==== %d %d ====\n",a,p);
    fprintf(stderr,"%d %d %d \r",p,tt,cc.tt);
    if(tt>1000000) break;
    
    vector<unsigned char> v,bf;
    int a=rand()%200;
    a+=10;
    v.resize(a);
    for(int i=0;i<a;i++)
      v[i]='a'+(rand()%26);

    // for(auto &it:v)
    //   printf("%c",it);
    // printf("\n");
    tt+=v.size();
    
    pthread_mutex_lock(&cc.m);

    while(cc.cc.size()>10000) {
      pthread_mutex_unlock(&cc.m);
      usleep(100000);
      if(!tc->check_alive()) break;
      if(tc->stream_is_closed(id)) break;
      pthread_mutex_lock(&cc.m);
    }
    for(auto &it:v)
      cc.cc.push_back(it);

    pthread_mutex_unlock(&cc.m);

    if(tc->streams[id].finished) break;
    
    tc->stream_send(id,v);

    if(tc->stream_is_closed(id)) break;
    if(!tc->check_alive()) break;
  }
  printf("stoping : do stream end\n");
  tc->stream_end(id);
  tc->destroy_circuit();
  delete tc;
  printf("test end\n");
}

void *test(void *) {
  circuit_t *tc=gen_working_circuit();

  if(tc==NULL) {
    LOG_FATAL("test(): gen_working_circuit fails: exiting 1\n");
    exit(1);
    return NULL;
  }

  test(tc,echo_host ,echo_port);


  LOG_INFO("end test()\n");
  //exit(0);
  return NULL;
}



#ifndef NOHS


#ifndef DISABLE_CACHE

///// TESTS ///////////
///// TESTS ///////////
///// TESTS ///////////


void read_onion_v3(const char *path="") {
  onion_key_t site,site2;
  site.read(path);
  site.print_info();
  site.check();

  site.generate();
  site.print_info();
  site.check();
  site.write("hspath/");
  site2.read("hspath/");
  site2.print_info();
  site2.check();
  
}


volatile char test_hs_ok=0;

void test_hs_cb(const unsigned char *t,int l)
{
  printf("test_hs_cb %p %d \n",t,l);
  if(t==NULL) {
    printf("special %s\n",get_ascb_type_str(ascb_type_t(l)));
    assert(l>=0 && l<3);
    if(l==ASCB_CONNECTED) {
      test_hs_ok=1;
    } else
      test_hs_ok=2; //Fail ?
  }
}

int test_hs(hsdirs_t &hsdirs) {

  for(auto &it:hsdirs.ids) {
    int ii=it;
    LOG_INFO("try to download HSDIR id node=%d\n",ii);

    circuit_t *tc=gen_working_circuit(&(cache_descs[ii]));
    if(!tc) {
      LOG_WARN("gen_working_circuit returns NULL !\n");
    } else {
      test_hs_ok=0;
      asocket_tor_t s(tc);

      s.set_ncb(test_hs_cb);

      s.begin_dir();
      // No!//tc->begin_dir(test_hs_cb);

      while(test_hs_ok==0) {
	printf("wait test_hs_ok...\n");
	usleep(200000);
      }

      if(test_hs_ok==1)  {
	LOG_INFO("connected to hsdir\n");
    
	hsdesc_processor_t *c=new hsdesc_processor_t();
	c->blinded_public_onion_key::operator=(hsdirs);

	if(c->download_hs_descriptor_in(s,*(s.get_exit_node()),hsdirs)) {
	  LOG_INFO("download_hs_descriptor_in ok !\n");
	}
      }
    }
    //if(hsdirs.intros.size()) break;
  }

  return hsdirs.intros.size();
}


void test_hs_server(string path="") {
#ifdef ESP
  esp_memory_info();
#endif
  
  hs_server_t *s=new hs_server_t(path);
  printf("hs_server_t() ok\n");

#ifdef MAXTIME
  sleep(MAXTIME);
#else
  while(!general_exit)
    sleep(1);
#endif
  printf("end : stop poller... \n");
  main_poller.stop();
  sleep(2);
  printf("end : finish... \n");
  s->finish();
  printf("end : finish done\n");
  sleep(3);
  printf("end : delete s = %p ... \n",s);
  delete s;
  printf("end : delete s done\n");
  sleep(2);
  printf("end : clean delete circuits... \n");
  clean_delete_circuit();
  sleep(2);
  printf("end end\n");
}

void test_hs_client(string arg="bar") {
  unsigned char r[32];
  //unsigned char h[32];
  string ad;
  
  if(arg=="ddg") 
    ad="duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"; //duckduckgo

  if(arg.size()>32)
    ad=arg;
  
  parse_onionv3(ad.c_str(),r);

  for(int no=0;no<NB_OLD;no++) {
    int dt=-1;
    if(relays.cons_hour<12)
      dt=0;
    else
      dt=-1;
    
    auto hsdirs=gen_hsdirs(r,l_get_time_period()+dt+no);

    LOG_INFO("dt=%d no=%d ....\n",dt,no);

    int nb=test_hs(hsdirs);
    
    LOG_INFO("test_hs() returns r=%d\n",nb);

#if 0
    if(nb) {
      
      for(auto &it:hsdirs.intros) {
	printf("===================>\n");
	it.print_info();
	printf("===================<\n");

	circuit_t *tc=NULL;
	circuit_t *tc2=NULL;
	info_node_t *n2=NULL;
	bool ok=1;
	
	rdv_material_t *rdv_material=new rdv_material_t();
	random_tab(rdv_material->rdvc,20);
	
	tc2=gen_working_circuit();
	if(!tc2) {
	  LOG_WARN("gen_working_circuit() (to rdv node) FAILED\n");
	  goto hs_c_fail;
	}
	LOG_INFO("== establish rendezvous  ==\n");
	tc2->establish_rendezvous(*rdv_material);

	LOG_INFO("== establish rendezvous done ==\n");

	n2=tc2->get_exit_node();
	  
	tc=gen_working_circuit(&it);
	if(!tc) {
	  LOG_WARN("gen_working_circuit() (to intro node) FAILED\n");
	  goto hs_c_fail;
	}
	  
	tc->intro1_protocol(it,*n2,*rdv_material);
	
	sleep(1);
    
	for(int i=0;i<200;i++) {
	  ok=0;
	  if((i%10)==0)
	    LOG_INFO("waiting for RDV...\n");
	  usleep(100*1000);
	  if(tc2->hs_circuit_built()) {
	    ok=1;
	    break;
	  }
	}
	
	if(ok) LOG_INFO("hs_circuit_built\n");
	else {
	  LOG_WARN("hs_circuit build fail\n");
	  goto      hs_c_fail;
	}

	LOG_SEVERE("TODO \n");
	
	//test(tc2,"",6666,0);
#if 0

	  socket_tor_t sr(tc2);
	  sr.connect("",6666);
	  while(1) {
	    sr.write((const unsigned char *)"PING",4);
	    char tt[11];
	    int r=sr.read((unsigned char *)tt,10);
	    //printf("client read r=%d\n",r);
	    if(r>0) {
	      tt[r]=0;
	      printf("client got : '%s'\n",tt);
	    }
	    sleep(1);
	  }
	  //test(&sr,echo_port);

#endif

      hs_c_fail:
	  if(tc) delete tc;
	  if(tc2) delete tc2;
	  
	
	  // sleep(2);
	  // printf("connect\n");
	  // auto stream_id=tc2->stream_start("",6666);

	  // for(int i=0;i<1000;i++) {
	  //   usleep(100*1000);
	  // }

	break;
	
      }
      break;
    }
#endif
  }
}

// int main(int ac, char **av) {
//   unsigned char r[40];
//   unsigned char h[32];
//   string ad="duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad";
//   if(ac>1) ad=av[1];
//   int res=parse_onionv3(ad.c_str(),r);
//   printf("res=%d\n",res);

//   print("pub:",r,32);
//   derive_blind_pub(r);

//   return 0;
// }

#else
void test_hs() {
  printf("DISABLE_CACHE set!\n");
}

void test_hs_client(const string &a="") {
  printf("DISABLE_CACHE set!\n");
}

void test_hs_server(const string &a="") {
  printf("DISABLE_CACHE set!\n");
}

void test_hs2() {
  printf("DISABLE_CACHE set!\n");
}


#endif
#endif
