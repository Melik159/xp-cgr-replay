#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>

#define CUDA_OK(x) do { cudaError_t _e=(x); if(_e!=cudaSuccess){fprintf(stderr,"CUDA error %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(_e)); exit(2);} } while(0)

#pragma pack(push,1)
struct Fixture {
    char magic[8];
    uint32_t version;
    uint8_t ksec_global[80];
    uint8_t fips[20];
    uint8_t pool0[600];
    uint8_t pool1[600];
    uint8_t before0[256];
    uint8_t before1[256];
    uint8_t qsi05_0[0xDC8];
    uint8_t qsi05_1[0xDC8];
    uint8_t qsi08_0[0xC0];
    uint8_t qsi08_1[0xC0];
    uint8_t sys0[32];
    uint8_t sys1[32];
    uint8_t sys2[32];
    uint8_t caller0[32];
    uint8_t caller1[32];
    uint32_t len0, len1, requested;
    uint8_t expected[32];
};
#pragma pack(pop)
static_assert(sizeof(Fixture)==9468,"fixture ABI");

enum SourceKind : int {
    SRC_ALLOCATOR=0, SRC_PID, SRC_TID, SRC_TICK, SRC_CPU,
    SRC_QSI03, SRC_QSI07, SRC_QSI02, SRC_QSI21, SRC_QSI2D,
    SRC_QSI05, SRC_QSI08, SRC_QSI17
};

struct SearchCfg {
    int event;
    int source;
    int offset;
    int lo;
    int hi;
    uint64_t total;
};

__constant__ Fixture d_fx;
__constant__ SearchCfg d_sc;

__host__ __device__ static inline uint32_t rol32(uint32_t x,int n){return (x<<n)|(x>>(32-n));}
__device__ __forceinline__ uint32_t load_be4(uint8_t a,uint8_t b,uint8_t c,uint8_t d){return ((uint32_t)a<<24)|((uint32_t)b<<16)|((uint32_t)c<<8)|d;}
__device__ __forceinline__ uint32_t load_le4(uint8_t a,uint8_t b,uint8_t c,uint8_t d){return ((uint32_t)d<<24)|((uint32_t)c<<16)|((uint32_t)b<<8)|a;}

__device__ __forceinline__ void sha1_rounds(uint32_t st[5], uint32_t w[16]) {
    uint32_t old0=st[0],old1=st[1],old2=st[2],old3=st[3],old4=st[4];
    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4];
    #pragma unroll 1
    for(int i=0;i<80;i++){
        uint32_t wi;
        if(i<16) wi=w[i];
        else { wi=rol32(w[(i-3)&15]^w[(i-8)&15]^w[(i-14)&15]^w[i&15],1); w[i&15]=wi; }
        uint32_t f,k;
        if(i<20){f=(b&c)|((~b)&d);k=0x5A827999u;}
        else if(i<40){f=b^c^d;k=0x6ED9EBA1u;}
        else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDCu;}
        else {f=b^c^d;k=0xCA62C1D6u;}
        uint32_t t=rol32(a,5)+f+e+k+wi;
        e=d; d=c; c=rol32(b,30); b=a; a=t;
    }
    st[0]=old0+a; st[1]=old1+b; st[2]=old2+c; st[3]=old3+d; st[4]=old4+e;
}

__device__ __forceinline__ uint8_t raw_hash_source_byte(int source,int event,int pos,uint8_t candidate){
    uint8_t v=0;
    if(source==SRC_QSI05) v = event==0 ? d_fx.qsi05_0[pos] : d_fx.qsi05_1[pos];
    else v = event==0 ? d_fx.qsi08_0[pos] : d_fx.qsi08_1[pos];
    if(pos==d_sc.offset) v=candidate;
    return v;
}

__device__ __forceinline__ void sha1_source_mutated(int source,int event,int len,uint8_t candidate,uint8_t out[20]){
    uint32_t st[5]={0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    int full=len/64, rem=len%64;
    #pragma unroll 1
    for(int blk=0;blk<full;blk++){
        uint32_t w[16];
        #pragma unroll
        for(int wi=0;wi<16;wi++){
            int p=blk*64+wi*4;
            w[wi]=load_be4(raw_hash_source_byte(source,event,p,candidate),
                           raw_hash_source_byte(source,event,p+1,candidate),
                           raw_hash_source_byte(source,event,p+2,candidate),
                           raw_hash_source_byte(source,event,p+3,candidate));
        }
        sha1_rounds(st,w);
    }
    int finals = (rem<=55)?1:2;
    uint64_t bits=(uint64_t)len*8ull;
    for(int fb=0;fb<finals;fb++){
        uint32_t w[16];
        #pragma unroll
        for(int wi=0;wi<16;wi++){
            uint8_t bb[4];
            #pragma unroll
            for(int k=0;k<4;k++){
                int p=fb*64+wi*4+k;
                uint8_t v=0;
                if(p<rem) v=raw_hash_source_byte(source,event,full*64+p,candidate);
                else if(p==rem) v=0x80;
                int total_final=finals*64;
                if(p>=total_final-8){
                    int q=p-(total_final-8);
                    v=(uint8_t)(bits>>(56-8*q));
                }
                bb[k]=v;
            }
            w[wi]=load_be4(bb[0],bb[1],bb[2],bb[3]);
        }
        sha1_rounds(st,w);
    }
    #pragma unroll
    for(int i=0;i<5;i++){out[4*i]=(uint8_t)(st[i]>>24);out[4*i+1]=(uint8_t)(st[i]>>16);out[4*i+2]=(uint8_t)(st[i]>>8);out[4*i+3]=(uint8_t)st[i];}
}

struct PoolPatch {
    int event;
    int base;
    int len;
    uint8_t bytes[20];
    int extra_pos;
    uint8_t extra_value;
};

__device__ __forceinline__ int direct_pool_base(int source){
    switch(source){
        case SRC_ALLOCATOR:return 0x000; case SRC_PID:return 0x008; case SRC_TID:return 0x010;
        case SRC_TICK:return 0x018; case SRC_CPU:return 0x028; case SRC_QSI03:return 0x050;
        case SRC_QSI07:return 0x088; case SRC_QSI02:return 0x0A8; case SRC_QSI21:return 0x1E8;
        case SRC_QSI2D:return 0x200; default:return -1;
    }
}

__device__ __forceinline__ PoolPatch make_patch(uint8_t candidate){
    PoolPatch p{}; p.event=d_sc.event; p.base=-1; p.len=0; p.extra_pos=-1; p.extra_value=0;
    if(d_sc.event>1) return p; // Events 2..7 do not affect the captured 32-byte output path.
    if(d_sc.source<=SRC_QSI2D){
        p.base=direct_pool_base(d_sc.source)+d_sc.offset; p.len=1; p.bytes[0]=candidate; return p;
    }
    if(d_sc.source==SRC_QSI17){
        p.base=0x240+d_sc.offset; p.len=1; p.bytes[0]=candidate; return p;
    }
    if(d_sc.source==SRC_QSI05 || d_sc.source==SRC_QSI08){
        p.base=(d_sc.source==SRC_QSI05)?0x038:0x228; p.len=20;
        int n=(d_sc.source==SRC_QSI05)?0xDC8:0xC0;
        sha1_source_mutated(d_sc.source,d_sc.event,n,candidate,p.bytes);
        if(d_sc.offset>=20 && d_sc.offset<24){p.extra_pos=p.base+d_sc.offset;p.extra_value=candidate;}
        return p;
    }
    return p;
}

__device__ __forceinline__ uint8_t baseline_pool_byte(int event,int pos){return event==0?d_fx.pool0[pos]:d_fx.pool1[pos];}
__device__ __forceinline__ uint8_t pool_byte(int event,int pos,const PoolPatch &p){
    if(event==p.event){
        if(p.len>0 && pos>=p.base && pos<p.base+p.len) return p.bytes[pos-p.base];
        if(pos==p.extra_pos) return p.extra_value;
    }
    return baseline_pool_byte(event,pos);
}

__device__ __forceinline__ uint8_t mix340_byte(int pos,const uint8_t *sA,int pool_id,int qA,const uint8_t *sB,int qB,const PoolPatch &p){
    if(pos<20) return sA[pos];
    if(pos<170) return pool_byte(pool_id,qA+(pos-20),p);
    if(pos<190) return sB[pos-170];
    return pool_byte(pool_id,qB+(pos-190),p);
}

__device__ __forceinline__ uint8_t ksec_final_byte_340(int rel,const uint8_t *sA,int pool_id,int qA,const uint8_t *sB,int qB,const PoolPatch &p){
    if(rel<20) return mix340_byte(320+rel,sA,pool_id,qA,sB,qB,p);
    if(rel==20) return 0x80;
    if(rel<56) return 0;
    constexpr uint64_t bits=340ull*8ull;
    uint32_t hi=(uint32_t)(bits>>32),lo=(uint32_t)bits;int k=rel-56;
    if(k<4) return (uint8_t)(hi>>(8*k)); k-=4; return (uint8_t)(lo>>(8*k));
}

__device__ __forceinline__ void ksec_hash_mix340(const uint8_t *sA,int pool_id,int qA,const uint8_t *sB,int qB,const PoolPatch &p,uint8_t out[20]){
    uint32_t st[5]={0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    #pragma unroll 1
    for(int blk=0;blk<5;blk++){
        uint32_t w[16];
        #pragma unroll
        for(int wi=0;wi<16;wi++){
            int q=blk*64+wi*4;
            w[wi]=load_le4(mix340_byte(q,sA,pool_id,qA,sB,qB,p),mix340_byte(q+1,sA,pool_id,qA,sB,qB,p),mix340_byte(q+2,sA,pool_id,qA,sB,qB,p),mix340_byte(q+3,sA,pool_id,qA,sB,qB,p));
        }
        sha1_rounds(st,w);
    }
    uint32_t w[16];
    #pragma unroll
    for(int wi=0;wi<16;wi++){
        int q=wi*4;
        w[wi]=load_be4(ksec_final_byte_340(q,sA,pool_id,qA,sB,qB,p),ksec_final_byte_340(q+1,sA,pool_id,qA,sB,qB,p),ksec_final_byte_340(q+2,sA,pool_id,qA,sB,qB,p),ksec_final_byte_340(q+3,sA,pool_id,qA,sB,qB,p));
    }
    sha1_rounds(st,w);
    #pragma unroll
    for(int i=0;i<5;i++){out[4*i]=(uint8_t)st[i];out[4*i+1]=(uint8_t)(st[i]>>8);out[4*i+2]=(uint8_t)(st[i]>>16);out[4*i+3]=(uint8_t)(st[i]>>24);}
}

__device__ __forceinline__ void ksec_hash40(const uint8_t x[20],const uint8_t y[20],uint8_t out[20]){
    uint32_t st[5]={0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    uint32_t w[16];
    #pragma unroll
    for(int wi=0;wi<16;wi++){
        uint8_t b4[4];
        #pragma unroll
        for(int k=0;k<4;k++){
            int p=wi*4+k; uint8_t v=0;
            if(p<20) v=x[p]; else if(p<40) v=y[p-20]; else if(p==40) v=0x80;
            else if(p>=56){constexpr uint64_t bits=40ull*8ull;uint32_t hi=(uint32_t)(bits>>32),lo=(uint32_t)bits;int q=p-56;v=(q<4)?(uint8_t)(hi>>(8*q)):(uint8_t)(lo>>(8*(q-4)));}
            b4[k]=v;
        }
        w[wi]=load_be4(b4[0],b4[1],b4[2],b4[3]);
    }
    sha1_rounds(st,w);
    #pragma unroll
    for(int i=0;i<5;i++){out[4*i]=(uint8_t)st[i];out[4*i+1]=(uint8_t)(st[i]>>8);out[4*i+2]=(uint8_t)(st[i]>>16);out[4*i+3]=(uint8_t)(st[i]>>24);}
}

__device__ __forceinline__ void replay_mixer(const uint8_t old[80],int event,const PoolPatch &p,uint8_t out[80]){
    uint8_t a[20],b[20],cc[20],d[20],aa[20],bb[20],ccc[20],dd[20];
    ksec_hash_mix340(old+0,event,0,old+20,150,p,a);
    ksec_hash_mix340(old+20,event,150,old+0,0,p,b);
    ksec_hash_mix340(old+40,event,300,old+60,450,p,cc);
    ksec_hash_mix340(old+60,event,450,old+40,300,p,d);
    ksec_hash40(a,cc,aa); ksec_hash40(b,d,bb); ksec_hash40(cc,a,ccc); ksec_hash40(d,b,dd);
    #pragma unroll
    for(int i=0;i<20;i++){out[i]=aa[i];out[20+i]=bb[i];out[40+i]=ccc[i];out[60+i]=dd[i];}
}

__device__ __forceinline__ uint8_t &SM(uint8_t *base,int pos,int lane,int stride){return base[pos*stride+lane];}
__device__ __forceinline__ void ksa_shared(const uint8_t *key,int keylen,uint8_t *A,int lane,int stride){
    for(int p=0;p<256;p++) SM(A,p,lane,stride)=(uint8_t)p; int j=0;
    #pragma unroll 1
    for(int i=0;i<256;i++){j=(j+(int)SM(A,i,lane,stride)+(int)key[i%keylen])&255;uint8_t t=SM(A,i,lane,stride);SM(A,i,lane,stride)=SM(A,j,lane,stride);SM(A,j,lane,stride)=t;}
}
__device__ __forceinline__ void derive_context(const uint8_t key80[80],const uint8_t *before,uint8_t *A,uint8_t *B,int lane,int stride){
    ksa_shared(key80,80,A,lane,stride); for(int p=0;p<256;p++) SM(B,p,lane,stride)=(uint8_t)p; uint8_t i=0,j=0; int j2=0;
    #pragma unroll 1
    for(int off=0;off<256;off++){i=(uint8_t)(i+1);j=(uint8_t)(j+SM(A,i,lane,stride));uint8_t t=SM(A,i,lane,stride);SM(A,i,lane,stride)=SM(A,j,lane,stride);SM(A,j,lane,stride)=t;uint8_t ks=SM(A,(uint8_t)(SM(A,i,lane,stride)+SM(A,j,lane,stride)),lane,stride);uint8_t keybyte=before[off]^ks;j2=(j2+(int)SM(B,off,lane,stride)+(int)keybyte)&255;t=SM(B,off,lane,stride);SM(B,off,lane,stride)=SM(B,j2,lane,stride);SM(B,j2,lane,stride)=t;}
}
__device__ __forceinline__ void rc4_replay20_shared(uint8_t *S,int lane,int stride,uint8_t &i,uint8_t &j,const uint8_t *in,uint8_t out[20]){
    #pragma unroll 1
    for(int off=0;off<20;off++){i=(uint8_t)(i+1);j=(uint8_t)(j+SM(S,i,lane,stride));uint8_t t=SM(S,i,lane,stride);SM(S,i,lane,stride)=SM(S,j,lane,stride);SM(S,j,lane,stride)=t;uint8_t k=SM(S,(uint8_t)(SM(S,i,lane,stride)+SM(S,j,lane,stride)),lane,stride);out[off]=in[off]^k;}
}
__device__ __forceinline__ void add160(const uint8_t a[20],const uint8_t b[20],uint16_t carry,uint8_t out[20]){
    #pragma unroll 1
    for(int i=19;i>=0;i--){uint16_t v=(uint16_t)a[i]+b[i]+carry;out[i]=(uint8_t)v;carry=(uint16_t)(v>>8);}
}
__device__ __forceinline__ void provider_compress(const uint8_t x[20],uint8_t out[20]){
    uint32_t st[5]={0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};uint32_t w[16];
    #pragma unroll
    for(int wi=0;wi<16;wi++){int p=wi*4;uint8_t a=p<20?x[p]:0,b=(p+1)<20?x[p+1]:0,c=(p+2)<20?x[p+2]:0,d=(p+3)<20?x[p+3]:0;w[wi]=load_be4(a,b,c,d);}sha1_rounds(st,w);
    #pragma unroll
    for(int i=0;i<5;i++){out[4*i]=(uint8_t)(st[i]>>24);out[4*i+1]=(uint8_t)(st[i]>>16);out[4*i+2]=(uint8_t)(st[i]>>8);out[4*i+3]=(uint8_t)st[i];}
}
__device__ __forceinline__ void provider_block(const uint8_t state[20],const uint8_t aux[20],uint8_t out40[40],uint8_t state_after[20]){
    uint8_t xa[20],oa[20],sa[20],xb[20],ob[20];
    add160(state,aux,0,xa);provider_compress(xa,oa);add160(state,oa,1,sa);add160(sa,aux,0,xb);provider_compress(xb,ob);add160(sa,ob,1,state_after);
    #pragma unroll
    for(int i=0;i<20;i++){out40[i]=oa[i];out40[20+i]=ob[i];}
}
__device__ __forceinline__ void provider_call_shared(uint8_t *S,int lane,int stride,uint8_t &i,uint8_t &j,const uint8_t fips[20],const uint8_t *sys,const uint8_t *caller,int len,uint8_t out40[40],uint8_t fips_after[20]){
    uint8_t raw[20];rc4_replay20_shared(S,lane,stride,i,j,sys,raw);uint8_t aux[20];int n=len<20?len:20;
    #pragma unroll
    for(int k=0;k<20;k++){uint8_t mixed=k<n?caller[k]:0;aux[k]=raw[k]^mixed;}provider_block(fips,aux,out40,fips_after);
}

__device__ __forceinline__ void cgr_for_value(uint8_t candidate,uint8_t out32[32],uint8_t *A,uint8_t *B,int lane,int stride){
    PoolPatch p=make_patch(candidate); uint8_t ks0[80],ks1[80]; replay_mixer(d_fx.ksec_global,0,p,ks0); replay_mixer(ks0,1,p,ks1);
    derive_context(ks0,d_fx.before0,A,B,lane,stride);uint8_t i0=0,j0=0,tmp20[20];rc4_replay20_shared(B,lane,stride,i0,j0,d_fx.sys0,tmp20);uint8_t init40[40],fips1[20];provider_call_shared(B,lane,stride,i0,j0,d_fx.fips,d_fx.sys1,d_fx.caller0,(int)d_fx.len0,init40,fips1);
    derive_context(ks1,d_fx.before1,A,B,lane,stride);uint8_t i1=0,j1=0,runtime40[40],fips2[20];provider_call_shared(B,lane,stride,i1,j1,fips1,d_fx.sys2,d_fx.caller1,(int)d_fx.len1,runtime40,fips2);
    #pragma unroll
    for(int k=0;k<32;k++) out32[k]=runtime40[k];
}

__device__ __forceinline__ uint64_t out_hash(const uint8_t out[32],uint64_t idx){
    uint64_t h=1469598103934665603ull^idx;
    #pragma unroll
    for(int i=0;i<32;i++){h^=out[i];h*=1099511628211ull;}return h;
}

__global__ void search_kernel(uint8_t *dump,uint64_t dump_count,unsigned long long *checksum){
    extern __shared__ uint8_t sh[];int lane=threadIdx.x,strideS=blockDim.x;uint8_t *A=sh,*B=sh+256*strideS;uint64_t gid=(uint64_t)blockIdx.x*blockDim.x+threadIdx.x,grid=(uint64_t)gridDim.x*blockDim.x;uint64_t local=0;
    for(uint64_t idx=gid;idx<d_sc.total;idx+=grid){
        uint8_t candidate=(uint8_t)(d_sc.lo+idx);uint8_t out[32];cgr_for_value(candidate,out,A,B,lane,strideS);
        if(dump&&idx<dump_count){
            #pragma unroll
            for(int k=0;k<32;k++) dump[idx*32+k]=out[k];
        }
        local^=out_hash(out,idx);
    }
    for(int off=16;off>0;off>>=1)local^=__shfl_xor_sync(0xffffffffu,local,off);if((threadIdx.x&31)==0)atomicXor(checksum,(unsigned long long)local);
}

static uint64_t parse_u64(const std::string&s){return std::stoull(s,nullptr,0);} 
static std::string hexn(const uint8_t*x,int n){static const char*h="0123456789abcdef";std::string s(n*2,'0');for(int i=0;i<n;i++){s[2*i]=h[x[i]>>4];s[2*i+1]=h[x[i]&15];}return s;}
static int source_id(const std::string&s){
    if(s=="allocator")return SRC_ALLOCATOR;if(s=="pid")return SRC_PID;if(s=="tid")return SRC_TID;if(s=="tick")return SRC_TICK;if(s=="cpu")return SRC_CPU;if(s=="qsi03")return SRC_QSI03;if(s=="qsi07")return SRC_QSI07;if(s=="qsi02")return SRC_QSI02;if(s=="qsi21")return SRC_QSI21;if(s=="qsi2d")return SRC_QSI2D;if(s=="qsi05")return SRC_QSI05;if(s=="qsi08")return SRC_QSI08;if(s=="qsi17")return SRC_QSI17;return -1;
}
static bool valid_offset(int src,int off){switch(src){case SRC_ALLOCATOR:case SRC_PID:case SRC_TID:return off>=0&&off<8;case SRC_TICK:case SRC_CPU:return off>=0&&off<16;case SRC_QSI03:return off>=0&&off<56;case SRC_QSI07:return off>=0&&off<32;case SRC_QSI02:return off>=0&&off<320;case SRC_QSI21:return off>=0&&off<24;case SRC_QSI2D:return off>=0&&off<40;case SRC_QSI05:return off>=0&&off<0xDC8;case SRC_QSI08:return off>=0&&off<0xC0;case SRC_QSI17:return off>=20&&off<24;default:return false;}}
struct Opt{std::string fixture,source,dump;int event=-1,offset=-1,lo=0,hi=255,threads=32,blocks=0;uint64_t max_trials=1000000ull;};
static void usage(){std::cerr<<"cgr-cuda-multisource --fixture run1.cgrmsv2 --event N --source NAME --offset N [--values 0:255] [--threads 32|64] [--dump out.bin]\n";exit(2);} 
static Opt args(int argc,char**argv){Opt o;for(int i=1;i<argc;){std::string k=argv[i++];auto need=[&](){if(i>=argc)usage();return std::string(argv[i++]);};if(k=="--fixture")o.fixture=need();else if(k=="--event")o.event=std::stoi(need());else if(k=="--source")o.source=need();else if(k=="--offset")o.offset=std::stoi(need());else if(k=="--values"){auto s=need();auto p=s.find(':');if(p==std::string::npos)usage();o.lo=std::stoi(s.substr(0,p),nullptr,0);o.hi=std::stoi(s.substr(p+1),nullptr,0);}else if(k=="--max-trials")o.max_trials=parse_u64(need());else if(k=="--threads")o.threads=std::stoi(need());else if(k=="--blocks")o.blocks=std::stoi(need());else if(k=="--dump")o.dump=need();else if(k=="-h"||k=="--help")usage();else{std::cerr<<"unknown "<<k<<"\n";usage();}}if(o.fixture.empty()||o.event<0||o.source.empty()||o.offset<0)usage();return o;}

int main(int argc,char**argv){
    try{
        Opt o=args(argc,argv);if(o.event<0||o.event>7){std::cerr<<"event must be 0..7\n";return 2;}int sid=source_id(o.source);if(sid<0||!valid_offset(sid,o.offset)){std::cerr<<"invalid source/offset\n";return 2;}if(o.lo<0||o.hi>255||o.lo>o.hi){std::cerr<<"bad values\n";return 2;}if(o.threads!=32&&o.threads!=64){std::cerr<<"threads must be 32 or 64\n";return 2;}
        Fixture fx{};std::ifstream f(o.fixture,std::ios::binary);if(!f.read((char*)&fx,sizeof(fx))||f.peek()!=EOF){std::cerr<<"bad fixture size\n";return 2;}if(std::memcmp(fx.magic,"CGRMSV2\0",8)||fx.version!=2){std::cerr<<"bad fixture magic/version\n";return 2;}
        uint64_t total=(uint64_t)(o.hi-o.lo+1);if(total>o.max_trials){std::cerr<<"search requires "<<total<<" > max-trials\n";return 2;}SearchCfg sc{o.event,sid,o.offset,o.lo,o.hi,total};CUDA_OK(cudaMemcpyToSymbol(d_fx,&fx,sizeof(fx)));CUDA_OK(cudaMemcpyToSymbol(d_sc,&sc,sizeof(sc)));
        int dev=0;cudaDeviceProp prop{};CUDA_OK(cudaGetDeviceProperties(&prop,dev));size_t shmem=(size_t)2*256*o.threads;if(shmem>prop.sharedMemPerBlock){std::cerr<<"shared memory request too large\n";return 2;}int active=0;CUDA_OK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&active,search_kernel,o.threads,shmem));int blocks=o.blocks?o.blocks:prop.multiProcessorCount*active;
        uint8_t *ddump=nullptr;uint64_t dump_count=0;if(!o.dump.empty()){dump_count=total;CUDA_OK(cudaMalloc(&ddump,(size_t)total*32));}unsigned long long *dchk;CUDA_OK(cudaMalloc(&dchk,8));unsigned long long z=0;CUDA_OK(cudaMemcpy(dchk,&z,8,cudaMemcpyHostToDevice));cudaEvent_t a,b;CUDA_OK(cudaEventCreate(&a));CUDA_OK(cudaEventCreate(&b));CUDA_OK(cudaEventRecord(a));search_kernel<<<blocks,o.threads,shmem>>>(ddump,dump_count,dchk);CUDA_OK(cudaGetLastError());CUDA_OK(cudaEventRecord(b));CUDA_OK(cudaEventSynchronize(b));float ms=0;CUDA_OK(cudaEventElapsedTime(&ms,a,b));unsigned long long chk=0;CUDA_OK(cudaMemcpy(&chk,dchk,8,cudaMemcpyDeviceToHost));if(ddump){std::vector<uint8_t> v((size_t)total*32);CUDA_OK(cudaMemcpy(v.data(),ddump,v.size(),cudaMemcpyDeviceToHost));std::ofstream q(o.dump,std::ios::binary);q.write((char*)v.data(),v.size());}
        double sec=ms/1000.0;std::cout<<"gpu="<<prop.name<<" sm="<<prop.multiProcessorCount<<" blocks="<<blocks<<" threads_per_block="<<o.threads<<" shared_per_block="<<shmem<<" occupancy_blocks_per_sm="<<active<<"\n";std::cout<<"fixture_expected="<<hexn(fx.expected,32)<<" search=ksec:"<<o.event<<":"<<o.source<<":"<<o.offset<<":"<<(o.offset+1)<<" values="<<o.lo<<":"<<o.hi<<" trials="<<total<<"\n";std::cout<<"CUDA_SEARCH_DONE trials="<<total<<" elapsed="<<sec<<"s rate="<<(double)total/sec<<"/s checksum=0x"<<std::hex<<chk<<std::dec<<"\n";if(ddump)std::cout<<"dump="<<o.dump<<" bytes="<<(total*32)<<"\n";
        cudaFree(ddump);cudaFree(dchk);cudaEventDestroy(a);cudaEventDestroy(b);return 0;
    }catch(const std::exception&e){std::cerr<<"error: "<<e.what()<<"\n";return 2;}
}
