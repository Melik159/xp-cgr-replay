use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Deserialize)]
struct StateFile {
    boundary: String,
    ksec_global_state_hex: Option<String>,
    provider_fips_state_hex: String,
    rc4_context_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourcesFile {
    ksec_events: Vec<KsecEvent>,
    provider_calls: Vec<ProviderCall>,
    requested_output_length: usize,
    systemfunction_inputs_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct KsecEvent {
    ksec_output_before_hex: String,
    sources: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ProviderCall {
    caller_buffer_before_hex: String,
    length: usize,
}

#[derive(Clone)]
struct Event {
    pool: [u8; 0x258],
    raw_sources: HashMap<String, Vec<u8>>,
    ksec_before: [u8; 256],
}

#[derive(Clone)]
struct Fixture {
    boundary: Boundary,
    ksec_global: [u8; 80],
    fips: [u8; 20],
    runtime_context: Option<[u8; 258]>,
    events: Vec<Event>,
    sys: Vec<[u8; 32]>,
    callers: Vec<[u8; 32]>,
    call_lengths: Vec<usize>,
    requested: usize,
}


#[derive(Clone)]
struct Precomputed {
    ks_after0: [u8; 80],
    ks_after1: [u8; 80],
    ctx0_before_sys0: [u8; 258],
    ctx0_after_sys0: [u8; 258],
    ctx1: [u8; 258],
    fips_after_init: [u8; 20],
    baseline_output: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    PreAcquisition,
    PreRuntime,
}

#[derive(Clone, Debug)]
enum TargetKind {
    KsecSource { event: usize, name: String },
    KsecBefore { event: usize },
    Sys { index: usize },
    Caller { index: usize },
}

#[derive(Clone, Debug)]
struct Target {
    kind: TargetKind,
    start: usize,
    end: usize,
    label: String,
}

impl Target {
    fn width(&self) -> usize { self.end - self.start }
}

#[derive(Default)]
struct Args {
    run: String,
    fixtures_root: Option<PathBuf>,
    boundary: String,
    search: Option<String>,
    values: (u8, u8),
    threads: Option<usize>,
    results: Option<PathBuf>,
    target_output: Option<Vec<u8>>,
    target_prefix: Option<Vec<u8>>,
    max_trials: u64,
    progress: u64,
    chunk: u64,
}

#[derive(Clone)]
struct Record {
    trial: u64,
    candidate: Vec<u8>,
    output: [u8; 32],
    hamming: u32,
}

fn usage() -> ! {
    eprintln!("cgr-fast --run run1 --search ksec:0:qsi17:20[:end] [options]\n\
Options:\n\
  --fixtures-root PATH   package root containing fixtures/\n\
  --boundary pre_acquisition|pre_runtime\n\
  --values MIN:MAX      inclusive byte domain, decimal or 0xNN\n\
  --threads auto|N      default: auto\n\
  --results PATH        deterministic JSONL output\n\
  --target-output HEX   stop on exact 32-byte output\n\
  --target-prefix HEX   stop on byte-aligned prefix\n\
  --max-trials N        default: 100000000\n\
  --progress N          print every N completed candidates; 0 disables\n\
  --chunk N             parallel chunk size, default 65536\n\
Search grammar:\n\
  ksec:<event>:<source>:<start>[:<end>]\n\
  ksec_before:<event>:<start>[:<end>]\n\
  sys:<index>:<start>[:<end>]\n\
  caller:<index>:<start>[:<end>]\n");
    std::process::exit(2);
}

fn parse_num(s: &str) -> Result<u64, String> {
    if let Some(rest) = s.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        run: "run1".to_string(),
        boundary: "pre_acquisition".to_string(),
        values: (0, 255),
        max_trials: 100_000_000,
        progress: 0,
        chunk: 65_536,
        ..Default::default()
    };
    let argv: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        let key = &argv[i];
        let need = |idx: usize| -> Result<&String, String> {
            argv.get(idx).ok_or_else(|| format!("missing value for {key}"))
        };
        match key.as_str() {
            "--run" => { a.run = need(i+1)?.clone(); i += 2; }
            "--fixtures-root" => { a.fixtures_root = Some(PathBuf::from(need(i+1)?)); i += 2; }
            "--boundary" => { a.boundary = need(i+1)?.clone(); i += 2; }
            "--search" => { a.search = Some(need(i+1)?.clone()); i += 2; }
            "--values" => {
                let v = need(i+1)?;
                let mut it = v.split(':');
                let lo = parse_num(it.next().ok_or("bad --values")?)?;
                let hi = parse_num(it.next().ok_or("bad --values")?)?;
                if it.next().is_some() || lo > hi || hi > 255 { return Err("--values must be MIN:MAX in 0..255".into()); }
                a.values = (lo as u8, hi as u8); i += 2;
            }
            "--threads" => {
                let v = need(i+1)?;
                a.threads = if v == "auto" { None } else {
                    let n = parse_num(v)? as usize;
                    if n == 0 { return Err("--threads must be >=1 or auto".into()); }
                    Some(n)
                };
                i += 2;
            }
            "--results" => { a.results = Some(PathBuf::from(need(i+1)?)); i += 2; }
            "--target-output" => {
                let b = decode_hex(need(i+1)?)?;
                if b.len() != 32 { return Err("--target-output must be 32 bytes".into()); }
                a.target_output = Some(b); i += 2;
            }
            "--target-prefix" => {
                let b = decode_hex(need(i+1)?)?;
                if b.len() > 32 { return Err("--target-prefix max 32 bytes".into()); }
                a.target_prefix = Some(b); i += 2;
            }
            "--max-trials" => { a.max_trials = parse_num(need(i+1)?)?; i += 2; }
            "--progress" => { a.progress = parse_num(need(i+1)?)?; i += 2; }
            "--chunk" => { a.chunk = parse_num(need(i+1)?)?; if a.chunk == 0 { return Err("--chunk must be >=1".into()); } i += 2; }
            "-h" | "--help" => usage(),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.target_output.is_some() && a.target_prefix.is_some() {
        return Err("choose only --target-output or --target-prefix".into());
    }
    Ok(a)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("odd-length hex".into()); }
    let mut out = Vec::with_capacity(s.len()/2);
    let bs = s.as_bytes();
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c-b'0'),
            b'a'..=b'f' => Some(c-b'a'+10),
            b'A'..=b'F' => Some(c-b'A'+10),
            _ => None,
        }
    }
    for i in (0..bs.len()).step_by(2) {
        let hi = nib(bs[i]).ok_or_else(|| "invalid hex".to_string())?;
        let lo = nib(bs[i+1]).ok_or_else(|| "invalid hex".to_string())?;
        out.push((hi<<4)|lo);
    }
    Ok(out)
}

fn hex(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len()*2);
    for &b in data {
        s.push(H[(b>>4) as usize] as char);
        s.push(H[(b&15) as usize] as char);
    }
    s
}

fn arr<const N: usize>(v: Vec<u8>, field: &str) -> Result<[u8; N], String> {
    v.try_into().map_err(|v: Vec<u8>| format!("{field}: expected {N} bytes, got {}", v.len()))
}

fn source_size(name: &str) -> Option<usize> {
    Some(match name {
        "allocator" => 0x08, "pid" => 0x08, "tid" => 0x08, "tick" => 0x10,
        "cpu" => 0x40, "qsi05" => 0xDC8, "qsi03" => 0x38, "qsi07" => 0x20,
        "qsi02" => 0x140, "qsi21" => 0x18, "qsi2d" => 0x28,
        "qsi08" => 0xC0, "qsi17" => 0x18,
        _ => return None,
    })
}

fn effective_source_range(name: &str) -> Option<(usize, usize)> {
    Some(match name {
        "allocator" => (0,8), "pid" => (0,8), "tid" => (0,8), "tick" => (0,16),
        "cpu" => (0,16), "qsi05" => (0,0xDC8), "qsi03" => (0,0x38),
        "qsi07" => (0,0x20), "qsi02" => (0,0x140), "qsi21" => (0,0x18),
        "qsi2d" => (0,0x28), "qsi08" => (0,0xC0), "qsi17" => (20,24),
        _ => return None,
    })
}

fn sha1_compress(mut state: [u32; 5], block: &[u8; 64], little_words: bool) -> [u32; 5] {
    let old = state;
    let mut w = [0u32; 80];
    for i in 0..16 {
        let j = i*4;
        w[i] = if little_words {
            u32::from_le_bytes([block[j],block[j+1],block[j+2],block[j+3]])
        } else {
            u32::from_be_bytes([block[j],block[j+1],block[j+2],block[j+3]])
        };
    }
    for i in 16..80 { w[i] = (w[i-3]^w[i-8]^w[i-14]^w[i-16]).rotate_left(1); }
    let (mut a,mut b,mut c,mut d,mut e)=(state[0],state[1],state[2],state[3],state[4]);
    for i in 0..80 {
        let (f,k)=if i<20 {((b&c)|((!b)&d),0x5A827999)} else if i<40 {(b^c^d,0x6ED9EBA1)} else if i<60 {((b&c)|(b&d)|(c&d),0x8F1BBCDC)} else {(b^c^d,0xCA62C1D6)};
        let t=a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
        e=d; d=c; c=b.rotate_left(30); b=a; a=t;
    }
    state[0]=old[0].wrapping_add(a); state[1]=old[1].wrapping_add(b); state[2]=old[2].wrapping_add(c); state[3]=old[3].wrapping_add(d); state[4]=old[4].wrapping_add(e);
    state
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut state=[0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0];
    let mut pos=0;
    while pos+64<=data.len() {
        let block: &[u8;64]=data[pos..pos+64].try_into().unwrap();
        state=sha1_compress(state,block,false); pos+=64;
    }
    let rem=&data[pos..];
    let mut tail=Vec::with_capacity(128); tail.extend_from_slice(rem); tail.push(0x80);
    while (tail.len()+8)%64!=0 { tail.push(0); }
    tail.extend_from_slice(&((data.len() as u64)*8).to_be_bytes());
    for chunk in tail.chunks_exact(64) {
        state=sha1_compress(state,chunk.try_into().unwrap(),false);
    }
    let mut out=[0u8;20];
    for (i,w) in state.iter().enumerate(){out[i*4..i*4+4].copy_from_slice(&w.to_be_bytes());}
    out
}

fn ksec_hash(message: &[u8]) -> [u8;20] {
    let mut state=[0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0];
    let complete=message.len()/64;
    for i in 0..complete {
        state=sha1_compress(state,message[i*64..(i+1)*64].try_into().unwrap(),true);
    }
    let rem=&message[complete*64..];
    let mut pad_len=64-(message.len()&0x3f);
    if pad_len<=8 {pad_len+=64;}
    let bit_len=(message.len() as u64)*8;
    let mut final_blocks=Vec::with_capacity(rem.len()+pad_len);
    final_blocks.extend_from_slice(rem); final_blocks.push(0x80);
    final_blocks.resize(final_blocks.len()+pad_len-9,0);
    final_blocks.extend_from_slice(&((bit_len>>32) as u32).to_le_bytes());
    final_blocks.extend_from_slice(&(bit_len as u32).to_le_bytes());
    for chunk in final_blocks.chunks_exact(64) {
        state=sha1_compress(state,chunk.try_into().unwrap(),false);
    }
    let mut out=[0u8;20];
    for (i,w) in state.iter().enumerate(){out[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());}
    out
}

fn replay_mixer(pool: &[u8;0x258], old: &[u8;80]) -> [u8;80] {
    let quarter=0x258/4; // 150
    let q=[&pool[0..quarter],&pool[quarter..2*quarter],&pool[2*quarter..3*quarter],&pool[3*quarter..4*quarter]];
    let s=[&old[0..20],&old[20..40],&old[40..60],&old[60..80]];
    let mix=|a:&[u8],b:&[u8],c:&[u8],d:&[u8]| {let mut m=Vec::with_capacity(a.len()+b.len()+c.len()+d.len());m.extend_from_slice(a);m.extend_from_slice(b);m.extend_from_slice(c);m.extend_from_slice(d);ksec_hash(&m)};
    let a=mix(s[0],q[0],s[1],q[1]); let b=mix(s[1],q[1],s[0],q[0]); let c=mix(s[2],q[2],s[3],q[3]); let d=mix(s[3],q[3],s[2],q[2]);
    let pair=|x:&[u8;20],y:&[u8;20]| {let mut m=[0u8;40];m[..20].copy_from_slice(x);m[20..].copy_from_slice(y);ksec_hash(&m)};
    let aa=pair(&a,&c); let bb=pair(&b,&d); let cc=pair(&c,&a); let dd=pair(&d,&b);
    let mut out=[0u8;80]; out[..20].copy_from_slice(&aa);out[20..40].copy_from_slice(&bb);out[40..60].copy_from_slice(&cc);out[60..80].copy_from_slice(&dd);out
}

fn rc4_ksa(key:&[u8])->[u8;258]{
    let mut out=[0u8;258]; for i in 0..256 {out[i]=i as u8;}
    let mut j=0usize;
    for i in 0..256 {j=(j+out[i] as usize+key[i%key.len()] as usize)&255;out.swap(i,j);}
    out
}

fn rc4_replay(mut st:[u8;258], input:&[u8], length:usize)->(Vec<u8>,[u8;258]){
    let mut i=st[256];let mut j=st[257];let mut out=Vec::with_capacity(length.min(input.len()));
    for off in 0..length {i=i.wrapping_add(1);j=j.wrapping_add(st[i as usize]);st.swap(i as usize,j as usize);if off<input.len(){out.push(input[off]^st[(st[i as usize].wrapping_add(st[j as usize])) as usize]);}}
    st[256]=i;st[257]=j;(out,st)
}

fn add160(a:&[u8;20],b:&[u8;20],carry0:u16)->[u8;20]{
    let mut out=[0u8;20];let mut carry=carry0;
    for i in (0..20).rev(){let v=a[i] as u16+b[i] as u16+carry;out[i]=v as u8;carry=v>>8;}out
}

fn provider_compress(xval:&[u8;20])->[u8;20]{
    let mut block=[0u8;64];block[..20].copy_from_slice(xval);
    let state=sha1_compress([0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0],&block,false);
    let mut out=[0u8;20];for(i,w)in state.iter().enumerate(){out[i*4..i*4+4].copy_from_slice(&w.to_be_bytes());}out
}

fn provider_block(state:&[u8;20],aux:&[u8;20])->([u8;40],[u8;20]){
    let xa=add160(state,aux,0);let oa=provider_compress(&xa);let sa=add160(state,&oa,1);let xb=add160(&sa,aux,0);let ob=provider_compress(&xb);let sb=add160(&sa,&ob,1);
    let mut out=[0u8;40];out[..20].copy_from_slice(&oa);out[20..].copy_from_slice(&ob);(out,sb)
}

fn provider_call(ctx:[u8;258],fips:[u8;20],sys:&[u8;32],caller:&[u8;32],len:usize)->([u8;40],[u8;20],[u8;258]){
    let(raw,ctx_after)=rc4_replay(ctx,sys,20);let mut mixed=[0u8;20];let n=len.min(20);mixed[..n].copy_from_slice(&caller[..n]);let mut aux=[0u8;20];for i in 0..20{aux[i]=raw[i]^mixed[i];}let(out,fips_after)=provider_block(&fips,&aux);(out,fips_after,ctx_after)
}

fn build_pool(raw:&HashMap<String,Vec<u8>>)->Result<[u8;0x258],String>{
    let mut p=[0u8;0x258];
    let get=|n:&str|raw.get(n).ok_or_else(||format!("missing source {n}"));
    p[..8].copy_from_slice(&get("allocator")?[..8]);
    let copies=[("pid",0x008,8),("tid",0x010,8),("tick",0x018,16),("cpu",0x028,16),("qsi03",0x050,0x38),("qsi07",0x088,0x20),("qsi02",0x0A8,0x140),("qsi21",0x1E8,0x18),("qsi2d",0x200,0x28)];
    for(n,o,l)in copies{p[o..o+l].copy_from_slice(&get(n)?[..l]);}
    for(n,o,payload,reserved)in [("qsi05",0x038,0xDC8,0x18),("qsi08",0x228,0xC0,0x18),("qsi17",0x240,0,0x18)]{
        let d=get(n)?;let h=sha1_digest(&d[..payload]);p[o..o+20].copy_from_slice(&h);p[o+20..o+reserved].copy_from_slice(&d[20..reserved]);
    }
    Ok(p)
}

fn load_fixture(root:&Path,run:&str,boundary:&str)->Result<Fixture,String>{
    let run_dir=root.join("fixtures").join(run);
    let state_name=if boundary=="pre_runtime"{"runtime_state_before.json"}else{"state_before.json"};
    let state:StateFile=serde_json::from_str(&fs::read_to_string(run_dir.join(state_name)).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let src:SourcesFile=serde_json::from_str(&fs::read_to_string(run_dir.join("sources.json")).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let fips=arr::<20>(decode_hex(&state.provider_fips_state_hex)?,"fips")?;
    let mut ksec_global=[0u8;80];
    if let Some(s)=state.ksec_global_state_hex.as_ref(){ksec_global=arr::<80>(decode_hex(s)?,"ksec_global")?;}
    let runtime_context=match state.rc4_context_hex.as_ref(){Some(s)=>Some(arr::<258>(decode_hex(s)?,"rc4_context")?),None=>None};
    let b=match state.boundary.as_str(){"pre_acquisition"=>Boundary::PreAcquisition,"pre_runtime"=>Boundary::PreRuntime,x=>return Err(format!("unsupported boundary {x}"))};
    if (boundary=="pre_runtime")!=(b==Boundary::PreRuntime){return Err("requested/state boundary mismatch".into());}
    if src.ksec_events.len()!=8||src.systemfunction_inputs_hex.len()!=3||src.provider_calls.len()!=2||src.requested_output_length!=32{return Err("fixture shape differs from validated campaign".into());}
    let mut events=Vec::new();
    for(ei,e)in src.ksec_events.iter().enumerate(){
        let mut raw=HashMap::new();for(n,h)in &e.sources{let v=decode_hex(h)?;if let Some(sz)=source_size(n){if v.len()!=sz{return Err(format!("event {ei} {n}: expected {sz}, got {}",v.len()));}}raw.insert(n.clone(),v);}
        let pool=build_pool(&raw)?;let kb=arr::<256>(decode_hex(&e.ksec_output_before_hex)?,"ksec_before")?;events.push(Event{pool,raw_sources:raw,ksec_before:kb});
    }
    let mut sys=Vec::new();for h in &src.systemfunction_inputs_hex{sys.push(arr::<32>(decode_hex(h)?,"sys")?);}
    let mut callers=Vec::new();let mut call_lengths=Vec::new();for c in &src.provider_calls{callers.push(arr::<32>(decode_hex(&c.caller_buffer_before_hex)?,"caller")?);call_lengths.push(c.length);}
    Ok(Fixture{boundary:b,ksec_global,fips,runtime_context,events,sys,callers,call_lengths,requested:src.requested_output_length})
}

fn parse_target(spec:&str,fx:&Fixture)->Result<Target,String>{
    let v:Vec<&str>=spec.split(':').collect();
    let pu=|s:&str|s.parse::<usize>().map_err(|_|format!("bad integer {s}"));
    let mk_range=|start:usize,end:Option<usize>,limit:usize|->Result<(usize,usize),String>{let e=end.unwrap_or(start+1);if start>=e||e>limit{return Err(format!("range {start}:{e} outside 0:{limit}"));}Ok((start,e))};
    match v.get(0).copied(){
        Some("ksec") if v.len()==4||v.len()==5=>{let ev=pu(v[1])?;if ev>=fx.events.len(){return Err("bad event".into());}let name=v[2].to_string();let sz=source_size(&name).ok_or("unknown source")?;let(s,e)=mk_range(pu(v[3])?,if v.len()==5{Some(pu(v[4])?)}else{None},sz)?;if let Some((a,b))=effective_source_range(&name){if s<a||e>b{return Err(format!("{name} output-effective range is {a}:{b}"));}}Ok(Target{kind:TargetKind::KsecSource{event:ev,name},start:s,end:e,label:spec.into()})},
        Some("ksec_before") if v.len()==3||v.len()==4=>{let ev=pu(v[1])?;if ev>=fx.events.len(){return Err("bad event".into());}let(s,e)=mk_range(pu(v[2])?,if v.len()==4{Some(pu(v[3])?)}else{None},256)?;Ok(Target{kind:TargetKind::KsecBefore{event:ev},start:s,end:e,label:spec.into()})},
        Some("sys") if v.len()==3||v.len()==4=>{let idx=pu(v[1])?;if idx>=3{return Err("sys index 0..2".into());}let(s,e)=mk_range(pu(v[2])?,if v.len()==4{Some(pu(v[3])?)}else{None},20)?;Ok(Target{kind:TargetKind::Sys{index:idx},start:s,end:e,label:spec.into()})},
        Some("caller") if v.len()==3||v.len()==4=>{let idx=pu(v[1])?;if idx>=2{return Err("caller index 0..1".into());}let lim=fx.call_lengths[idx].min(20);let(s,e)=mk_range(pu(v[2])?,if v.len()==4{Some(pu(v[3])?)}else{None},lim)?;Ok(Target{kind:TargetKind::Caller{index:idx},start:s,end:e,label:spec.into()})},
        _=>Err("bad search spec".into())
    }
}

fn mutated_pool(event:&Event,target:Option<&Target>,candidate:&[u8],event_idx:usize)->[u8;0x258]{
    let mut p=event.pool;
    let Some(t)=target else{return p};
    let TargetKind::KsecSource{event:ev,name}= &t.kind else{return p};
    if *ev!=event_idx{return p;}
    let mut data=event.raw_sources.get(name).unwrap().clone();data[t.start..t.end].copy_from_slice(candidate);
    match name.as_str(){
        "allocator"=>p[t.start..t.end].copy_from_slice(candidate),
        "pid"|"tid"|"tick"|"cpu"|"qsi03"|"qsi07"|"qsi02"|"qsi21"|"qsi2d"=>{
            let o=match name.as_str(){"pid"=>0x008,"tid"=>0x010,"tick"=>0x018,"cpu"=>0x028,"qsi03"=>0x050,"qsi07"=>0x088,"qsi02"=>0x0A8,"qsi21"=>0x1E8,"qsi2d"=>0x200,_=>0};
            p[o+t.start..o+t.end].copy_from_slice(candidate);
        }
        "qsi05"|"qsi08"|"qsi17"=>{
            let(o,payload,reserved)=match name.as_str(){"qsi05"=>(0x038,0xDC8,0x18),"qsi08"=>(0x228,0xC0,0x18),_=>(0x240,0,0x18)};
            let h=sha1_digest(&data[..payload]);p[o..o+20].copy_from_slice(&h);p[o+20..o+reserved].copy_from_slice(&data[20..reserved]);
        }
        _=>unreachable!(),
    }
    p
}

fn mutated_32(base:&[u8;32],target:Option<&Target>,candidate:&[u8],kind:&str,index:usize)->[u8;32]{
    let mut x=*base;let Some(t)=target else{return x};let hit=match(&t.kind,kind){(TargetKind::Sys{index:i},"sys")=>*i==index,(TargetKind::Caller{index:i},"caller")=>*i==index,_=>false};if hit{x[t.start..t.end].copy_from_slice(candidate);}x
}

fn mutated_ksec_before(base:&[u8;256],target:Option<&Target>,candidate:&[u8],event:usize)->[u8;256]{
    let mut x=*base;if let Some(t)=target{if let TargetKind::KsecBefore{event:e}=&t.kind{if *e==event{x[t.start..t.end].copy_from_slice(candidate);}}}x
}

fn context_from_event(ks: &[u8;80], event: &Event, before: &[u8;256]) -> [u8;258] {
    let kctx=rc4_ksa(ks);
    let(kout,_)=rc4_replay(kctx,before,256);
    rc4_ksa(&kout)
}

fn runtime_output(fx:&Fixture,ctx1:[u8;258],fips:[u8;20],target:Option<&Target>,candidate:&[u8])->[u8;32]{
    let sys2=mutated_32(&fx.sys[2],target,candidate,"sys",2);
    let call1=mutated_32(&fx.callers[1],target,candidate,"caller",1);
    let(out,_,_)=provider_call(ctx1,fips,&sys2,&call1,fx.call_lengths[1]);
    let mut r=[0u8;32];r.copy_from_slice(&out[..fx.requested]);r
}

fn precompute(fx:&Fixture)->Option<Precomputed>{
    if fx.boundary==Boundary::PreRuntime{return None;}
    let ks_after0=replay_mixer(&fx.events[0].pool,&fx.ksec_global);
    let ctx0_before_sys0=context_from_event(&ks_after0,&fx.events[0],&fx.events[0].ksec_before);
    let(_,ctx0_after_sys0)=rc4_replay(ctx0_before_sys0,&fx.sys[0],20);
    let ks_after1=replay_mixer(&fx.events[1].pool,&ks_after0);
    let ctx1=context_from_event(&ks_after1,&fx.events[1],&fx.events[1].ksec_before);
    let(_,fips_after_init,_)=provider_call(ctx0_after_sys0,fx.fips,&fx.sys[1],&fx.callers[0],fx.call_lengths[0]);
    let baseline_output=runtime_output(fx,ctx1,fips_after_init,None,&[]);
    Some(Precomputed{ks_after0,ks_after1,ctx0_before_sys0,ctx0_after_sys0,ctx1,fips_after_init,baseline_output})
}

fn predict_output(fx:&Fixture,pc:Option<&Precomputed>,target:Option<&Target>,candidate:&[u8])->[u8;32]{
    if fx.boundary==Boundary::PreRuntime {
        let sys2=mutated_32(&fx.sys[2],target,candidate,"sys",2);let c1=mutated_32(&fx.callers[1],target,candidate,"caller",1);let(out,_,_)=provider_call(fx.runtime_context.unwrap(),fx.fips,&sys2,&c1,fx.call_lengths[1]);let mut r=[0u8;32];r.copy_from_slice(&out[..32]);return r;
    }
    let pc=pc.expect("pre_acquisition precompute");
    let Some(t)=target else{return pc.baseline_output;};
    match &t.kind {
        TargetKind::KsecSource{event,name:_} if *event==0 => {
            let p0=mutated_pool(&fx.events[0],Some(t),candidate,0);
            let ks0=replay_mixer(&p0,&fx.ksec_global);
            let mut ctx0=context_from_event(&ks0,&fx.events[0],&fx.events[0].ksec_before);
            let(_,ctx0s)=rc4_replay(ctx0,&fx.sys[0],20);ctx0=ctx0s;
            let ks1=replay_mixer(&fx.events[1].pool,&ks0);
            let ctx1=context_from_event(&ks1,&fx.events[1],&fx.events[1].ksec_before);
            let(_,fips,_)=provider_call(ctx0,fx.fips,&fx.sys[1],&fx.callers[0],fx.call_lengths[0]);
            runtime_output(fx,ctx1,fips,None,&[])
        }
        TargetKind::KsecSource{event,name:_} if *event==1 => {
            let p1=mutated_pool(&fx.events[1],Some(t),candidate,1);
            let ks1=replay_mixer(&p1,&pc.ks_after0);
            let ctx1=context_from_event(&ks1,&fx.events[1],&fx.events[1].ksec_before);
            runtime_output(fx,ctx1,pc.fips_after_init,None,&[])
        }
        TargetKind::KsecSource{event,..} if *event>1 => pc.baseline_output,
        TargetKind::KsecBefore{event} if *event==0 => {
            let kb=mutated_ksec_before(&fx.events[0].ksec_before,Some(t),candidate,0);
            let ctx0b=context_from_event(&pc.ks_after0,&fx.events[0],&kb);
            let(_,ctx0)=rc4_replay(ctx0b,&fx.sys[0],20);
            let(_,fips,_)=provider_call(ctx0,fx.fips,&fx.sys[1],&fx.callers[0],fx.call_lengths[0]);
            runtime_output(fx,pc.ctx1,fips,None,&[])
        }
        TargetKind::KsecBefore{event} if *event==1 => {
            let kb=mutated_ksec_before(&fx.events[1].ksec_before,Some(t),candidate,1);
            let ctx1=context_from_event(&pc.ks_after1,&fx.events[1],&kb);
            runtime_output(fx,ctx1,pc.fips_after_init,None,&[])
        }
        TargetKind::KsecBefore{event} if *event>1 => pc.baseline_output,
        TargetKind::Sys{index} if *index==0 => {
            let sys0=mutated_32(&fx.sys[0],Some(t),candidate,"sys",0);
            let(_,ctx0)=rc4_replay(pc.ctx0_before_sys0,&sys0,20);
            let(_,fips,_)=provider_call(ctx0,fx.fips,&fx.sys[1],&fx.callers[0],fx.call_lengths[0]);
            runtime_output(fx,pc.ctx1,fips,None,&[])
        }
        TargetKind::Sys{index} if *index==1 => {
            let sys1=mutated_32(&fx.sys[1],Some(t),candidate,"sys",1);
            let(_,fips,_)=provider_call(pc.ctx0_after_sys0,fx.fips,&sys1,&fx.callers[0],fx.call_lengths[0]);
            runtime_output(fx,pc.ctx1,fips,None,&[])
        }
        TargetKind::Caller{index} if *index==0 => {
            let c0=mutated_32(&fx.callers[0],Some(t),candidate,"caller",0);
            let(_,fips,_)=provider_call(pc.ctx0_after_sys0,fx.fips,&fx.sys[1],&c0,fx.call_lengths[0]);
            runtime_output(fx,pc.ctx1,fips,None,&[])
        }
        TargetKind::Sys{index} if *index==2 => runtime_output(fx,pc.ctx1,pc.fips_after_init,Some(t),candidate),
        TargetKind::Caller{index} if *index==1 => runtime_output(fx,pc.ctx1,pc.fips_after_init,Some(t),candidate),
        _ => pc.baseline_output,
    }
}

fn candidate_from_index(mut index:u64,lo:u8,hi:u8,width:usize)->Vec<u8>{
    let card=(hi as u16 - lo as u16 + 1) as u64;let mut out=vec![lo;width];for pos in (0..width).rev(){out[pos]=lo+(index%card) as u8;index/=card;}out
}

fn hamming(a:&[u8;32],b:&[u8;32])->u32{a.iter().zip(b).map(|(x,y)|(x^y).count_ones()).sum()}

fn hit(out:&[u8;32],args:&Args)->bool{
    if let Some(t)=&args.target_output{return out.as_slice()==t.as_slice();}
    if let Some(p)=&args.target_prefix{return out.starts_with(p);}
    false
}

fn write_record<W:Write>(w:&mut W,r:&Record,target:&str)->std::io::Result<()> {
    writeln!(w,"{{\"candidate_hex\":\"{}\",\"hamming_from_baseline\":{},\"output_hex\":\"{}\",\"target\":\"{}\",\"trial\":{}}}",hex(&r.candidate),r.hamming,hex(&r.output),target,r.trial)
}

fn main(){
    let args=parse_args().unwrap_or_else(|e|{eprintln!("error: {e}");usage()});
    let root=args.fixtures_root.clone().unwrap_or_else(||PathBuf::from("."));
    let fx=load_fixture(&root,&args.run,&args.boundary).unwrap_or_else(|e|{eprintln!("fixture error: {e}");std::process::exit(2)});
    let target=args.search.as_ref().map(|s|parse_target(s,&fx).unwrap_or_else(|e|{eprintln!("target error: {e}");std::process::exit(2)}));
    if fx.boundary==Boundary::PreRuntime {if let Some(t)=&target{match &t.kind{TargetKind::KsecSource{..}|TargetKind::KsecBefore{..}=>{eprintln!("pre_runtime does not consume KSec inputs");std::process::exit(2)},TargetKind::Sys{index} if *index!=2=>{eprintln!("pre_runtime consumes only sys:2");std::process::exit(2)},TargetKind::Caller{index} if *index!=1=>{eprintln!("pre_runtime consumes only caller:1");std::process::exit(2)},_=>{}}}}
    let pc=precompute(&fx);let zero:Vec<u8>=Vec::new();let baseline=predict_output(&fx,pc.as_ref(),None,&zero);
    println!("run={} boundary={}",args.run,args.boundary);println!("baseline_output={}",hex(&baseline));
    let Some(target)=target else{return};
    if let TargetKind::KsecSource{event,..}|TargetKind::KsecBefore{event}=&target.kind {if *event>1{eprintln!("warning: event {event} is output-ineffective for the validated 32-byte path; output will remain constant although full post-state may change");}}
    let card=(args.values.1 as u16 - args.values.0 as u16 + 1) as u64;let mut total=1u64;for _ in 0..target.width(){total=total.checked_mul(card).unwrap_or(u64::MAX);}if total>args.max_trials{eprintln!("search requires {total} trials > --max-trials {}",args.max_trials);std::process::exit(2)}
    let threads=args.threads.unwrap_or_else(||std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1));
    let pool=ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    println!("cpu_threads={} search={} width={} values={}:{} trials={}",threads,target.label,target.width(),args.values.0,args.values.1,total);
    let mut writer=args.results.as_ref().map(|p|BufWriter::new(File::create(p).unwrap()));let start=Instant::now();let mut completed=0u64;let mut found:Option<Record>=None;
    while completed<total && found.is_none(){
        let end=(completed+args.chunk).min(total);
        let records:Vec<Record>=pool.install(||(completed..end).into_par_iter().map(|idx|{let c=candidate_from_index(idx,args.values.0,args.values.1,target.width());let o=predict_output(&fx,pc.as_ref(),Some(&target),&c);Record{trial:idx+1,candidate:c,output:o,hamming:hamming(&baseline,&o)}}).collect());
        for r in &records {if let Some(w)=writer.as_mut(){write_record(w,r,&target.label).unwrap();}if hit(&r.output,&args){found=Some(r.clone());break;}}
        completed=found.as_ref().map(|r|r.trial).unwrap_or(end);if args.progress>0 && completed%args.progress<args.chunk{let e=start.elapsed().as_secs_f64().max(1e-9);eprintln!("progress={}/{} rate={:.1}/s",completed,total,completed as f64/e);}
    }
    if let Some(w)=writer.as_mut(){w.flush().unwrap();}
    let elapsed=start.elapsed().as_secs_f64();if let Some(r)=&found{println!("MATCH trial={} candidate={} output={}",r.trial,hex(&r.candidate),hex(&r.output));}
    println!("SEARCH_DONE target={} trials={}/{} elapsed={:.6}s rate={:.2}/s match={}",target.label,completed,total,elapsed,completed as f64/elapsed.max(1e-9),if found.is_some(){"YES"}else{"NO"});
    if let Some(p)=args.results{println!("results={}",p.display());}
}
