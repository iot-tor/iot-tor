
struct test_t {
  int tt=0;
  vector<unsigned char> cc;
  pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;

  void test_cb(const unsigned char *d,int l) {
    if(d==NULL) {
      printf("special l=%d\n",l);
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

  LOG_INFO("tor test() starts");
  
  if(!host.empty() && !is_ipv4_address(host)) {
    tc->stream_resolve(host);
  }
  
  LOG_INFO("tor test() resolve done ");
  
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


#if 1
int test_hs(hsdirs_t &hsdirs) {

  for(auto &it:hsdirs.ids) {
    int ii=it;
    printf("HSDIRXXX %d xxxx \n",ii);
    
    socket_tor_t s;
    s.set_timeout(10*1000+101);

    s.connect_dir_and_wait(&(cache_descs[ii]));
    
    hsdesc_processor_t *c=new hsdesc_processor_t();
    c->blinded_public_onion_key::operator=(hsdirs);

    if(c->download_hs_descriptor_in(s,*(s.get_exit_node()),hsdirs)) {
      printf("download_hs_descriptor_in ok !\n");
    }

    if(hsdirs.intros.size()) break;
  }
  //exit(0);
  return hsdirs.intros.size();
}
#endif


void test_hs_server() {
  hs_server_t *s=new hs_server_t;
  s->init();
  printf("hs_server_t::init() ends\n");
  delete s;
}

void test_hs_client(string arg="3") {
  unsigned char r[32];
  //unsigned char h[32];
  string ad;
  if(arg=="ddg") 
    ad="duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"; //duckduckgo
  if(arg=="bar") 
    ad="olngj26saap7cjpvof7pyiqhi5m7sgc7u342hynjr7b6cczb42dtfxad"; //tor@bar
  if(arg=="mini") 
    ad="homnvsuojcsoihii3zqwgxl7f3cvytyph5celhthaft52llx2xkwxaqd"; //minitor
  if(arg=="echo")
    ad="yod6updiziffvye22wpe2jcmsruxjyautfiqknkstflqawvyumd5xdqd"; //echo server
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

    printf("ZZZZZZZ dt=%d no=%d ....\n",dt,no);

    int nb=test_hs(hsdirs);
  
    printf("ZZZZZZZ dt=%d no=%d r=%d\n",dt,no,nb);

    if(nb) {

#if 1
      for(auto &it:hsdirs.intros) {
	printf("===================>\n");
	it.print_info();
	printf("===================<\n");
	circuit_t *tc=new circuit_t();

	rdv_material_t *rdv_material=new rdv_material_t();
	random_tab(rdv_material->rdvc,20);
    

    
#if 1
	circuit_t *tc2;
	while(1) {
	  printf("== build circuit ==\n");
	  tc2=new circuit_t();
	  fill_nodes(tc2);
	  if(tc2->build_circuit()) {
	    break;
	  }
	  delete tc2;
	}
	printf("== establish rendezvous  ==\n");
	tc2->establish_rendezvous(*rdv_material);
#endif

	printf("===================\n");
	printf("====== OK 1 =======\n");
	printf("===================\n");
          

	auto n2=tc2->get_exit_node();


	fill_nodes(tc,&it);
	tc->build_circuit();
	tc->intro1_protocol(it,*n2,*rdv_material);

	sleep(1);
    
	for(int i=0;i<100;i++) {
	  usleep(100*1000);
	  if(tc2->hs_circuit_built())
	    break;
	}

	printf("OK2\n");
    
	//test(tc2,"",6666,0);

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

	// sleep(2);
	// printf("connect\n");
	// auto stream_id=tc2->stream_start("",6666);

	// for(int i=0;i<1000;i++) {
	//   usleep(100*1000);
	// }

	break;
	
      }
#endif
      break;
    }
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
