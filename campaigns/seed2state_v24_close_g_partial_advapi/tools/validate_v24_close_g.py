#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load_events(path):
    return [json.loads(line) for line in open(path, encoding='utf-8')]


def read_dump(ev):
    d = ev.get('dump')
    if not d:
        return None
    return Path(d['file']).read_bytes()


def eval_dec(ev):
    e = ev.get('eval')
    if not e:
        return None
    return e.get('dec')


def rc4_prga_bytes(S, i, j, n):
    S = list(S)
    out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xff])
    return bytes(out), bytes(S), i, j


def ksa_bytes(key):
    S = list(range(256))
    j = 0
    if not key:
        return bytes(S), 0, 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return bytes(S), 0, 0


class Layout:
    def __init__(self, name, get, put):
        self.name = name
        self.get = get
        self.put = put


def layouts():
    def get_s0_xy100(buf):
        if len(buf) < 0x102: return None
        return bytes(buf[0:0x100]), buf[0x100], buf[0x101]
    def put_s0_xy100(S,i,j,orig):
        b = bytearray(orig)
        b[0:0x100] = S
        b[0x100] = i & 0xff
        b[0x101] = j & 0xff
        return bytes(b)

    def get_s0_xy104(buf):
        if len(buf) < 0x108: return None
        i = int.from_bytes(buf[0x100:0x104], 'little') & 0xff
        j = int.from_bytes(buf[0x104:0x108], 'little') & 0xff
        return bytes(buf[0:0x100]), i, j
    def put_s0_xy104(S,i,j,orig):
        b = bytearray(orig)
        b[0:0x100] = S
        b[0x100:0x104] = int(i).to_bytes(4,'little')
        b[0x104:0x108] = int(j).to_bytes(4,'little')
        return bytes(b)

    def get_xy0_s8(buf):
        if len(buf) < 0x108: return None
        i = int.from_bytes(buf[0:4], 'little') & 0xff
        j = int.from_bytes(buf[4:8], 'little') & 0xff
        return bytes(buf[8:0x108]), i, j
    def put_xy0_s8(S,i,j,orig):
        b = bytearray(orig)
        b[0:4] = int(i).to_bytes(4,'little')
        b[4:8] = int(j).to_bytes(4,'little')
        b[8:0x108] = S
        return bytes(b)

    def get_xy0_s4(buf):
        if len(buf) < 0x104: return None
        i = buf[0]
        j = buf[1]
        return bytes(buf[4:0x104]), i, j
    def put_xy0_s4(S,i,j,orig):
        b = bytearray(orig)
        b[0] = i & 0xff
        b[1] = j & 0xff
        b[4:0x104] = S
        return bytes(b)

    return [
        Layout('S@0+i8@0x100+j8@0x101', get_s0_xy100, put_s0_xy100),
        Layout('S@0+i32@0x100+j32@0x104', get_s0_xy104, put_s0_xy104),
        Layout('i32@0+j32@4+S@8', get_xy0_s8, put_xy0_s8),
        Layout('i8@0+j8@1+S@4', get_xy0_s4, put_xy0_s4),
    ]


def add_to_current(target, ev, name):
    if target is None:
        return
    m = ev['marker']
    if m.endswith('_ARG_LEN_T5') or m.endswith('_KEY_ARG_KEYLEN_T9'):
        target['len'] = eval_dec(ev)
    elif m.endswith('_ARG_STATE_T4') or m.endswith('_KEY_ARG_STATE_T8'):
        target['state_ptr'] = eval_dec(ev)
    elif m.endswith('_ARG_OUT_BEGIN_T7'):
        target['out_ptr'] = eval_dec(ev)
    elif m.endswith('_ARG_KEYBUF_T3'):
        target['key_ptr'] = eval_dec(ev)
    elif name:
        data = read_dump(ev)
        if data is not None:
            target[name] = data


def build_cycles(events):
    cycles=[]; cur=None; cur_call=None; cur_return=None; cur_key=None
    for ev in events:
        m=ev['marker']
        if m=='V24_CLOSEG_NEWGENEX_ENTRY_F7459951':
            if cur: cycles.append(cur)
            cur={'entry_line':ev['line'], 'rc4':[], 'keys':[], 'after':None, 'pre':None, 'advapi':None, 'vlh':0}
            cur_call=None; cur_return=None; cur_key=None
        elif cur is None:
            continue
        elif m=='V24_CLOSEG_VLH_CHECKPOINT_F7459724':
            cur['vlh'] += 1
        elif m=='V24_CLOSEG_RC4_ENTRY_F745F010':
            cur_call={'entry_line':ev['line']}
            cur['rc4'].append(cur_call)
            cur_return=None; cur_key=None
        elif m=='V24_CLOSEG_RC4_RETURN_F745F15A':
            # attach to the most recent call without a return; otherwise to latest call
            candidates=[c for c in cur['rc4'] if 'return_line' not in c]
            cur_return = candidates[-1] if candidates else (cur['rc4'][-1] if cur['rc4'] else None)
            if cur_return is not None:
                cur_return['return_line']=ev['line']
            cur_call=None; cur_key=None
        elif m=='V24_CLOSEG_RC4_KEY_ENTRY_F745F15D':
            cur_key={'entry_line':ev['line']}
            cur['keys'].append(cur_key)
            cur_call=None; cur_return=None
        elif m=='V24_CLOSEG_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100':
            cur['after']=read_dump(ev)
        elif m=='V24_CLOSEG_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100':
            cur['pre']=read_dump(ev)
        elif m=='V24_CLOSEG_ADVAPI_IOCTL_OUTBUF_100':
            cur['advapi']=read_dump(ev)
        elif m=='V24_CLOSEG_RC4_ARG_STATE_T4':
            add_to_current(cur_call, ev, None)
        elif m=='V24_CLOSEG_RC4_ARG_LEN_T5':
            add_to_current(cur_call, ev, None)
        elif m=='V24_CLOSEG_RC4_ARG_OUT_BEGIN_T7':
            add_to_current(cur_call, ev, None)
        elif m=='V24_CLOSEG_RC4_OUTBUF_BEFORE_100':
            add_to_current(cur_call, ev, 'out_before')
        elif m=='V24_CLOSEG_RC4_STATE_ENTRY_120':
            add_to_current(cur_call, ev, 'state_entry')
        elif m=='V24_CLOSEG_RC4_RETURN_ARG_STATE_T4':
            add_to_current(cur_return, ev, None)
        elif m=='V24_CLOSEG_RC4_RETURN_ARG_LEN_T5':
            add_to_current(cur_return, ev, None)
        elif m=='V24_CLOSEG_RC4_RETURN_ARG_OUT_BEGIN_T7':
            add_to_current(cur_return, ev, None)
        elif m=='V24_CLOSEG_RC4_OUTBUF_RETURN_100':
            add_to_current(cur_return, ev, 'out_return')
        elif m=='V24_CLOSEG_RC4_STATE_RETURN_120':
            add_to_current(cur_return, ev, 'state_return')
        elif m=='V24_CLOSEG_RC4_KEY_ARG_STATE_T8':
            add_to_current(cur_key, ev, None)
        elif m=='V24_CLOSEG_RC4_KEY_ARG_KEYLEN_T9':
            add_to_current(cur_key, ev, None)
        elif m=='V24_CLOSEG_RC4_KEY_ARG_KEYBUF_T3':
            add_to_current(cur_key, ev, None)
        elif m=='V24_CLOSEG_RC4_KEY_STATE_BEFORE_120':
            add_to_current(cur_key, ev, 'state_before')
        elif m=='V24_CLOSEG_RC4_KEY_KEYBUF_100':
            add_to_current(cur_key, ev, 'keybuf')
    if cur: cycles.append(cur)
    return cycles


def validate_transport(cycles):
    ok=0
    rows=[]
    for i,c in enumerate(cycles,1):
        match = c['after'] is not None and c['pre'] is not None and c['advapi'] is not None and c['after'][:0x100]==c['pre'][:0x100]==c['advapi'][:0x100]
        if match: ok += 1
        rows.append((i, c['entry_line'], c['vlh'], len(c['rc4']), len(c['keys']), bool(match)))
    return ok, rows


def validate_prga(cycles):
    total=0; ok=0; detail=[]
    for ci,c in enumerate(cycles,1):
        for ri,call in enumerate(c['rc4'],1):
            needed = ('state_entry','out_return','len')
            if not all(k in call and call[k] is not None for k in needed):
                detail.append((ci,ri,'missing',False,'missing entry/return/len'))
                continue
            n = min(call['len'] or 0, len(call.get('out_return',b'')))
            if n <= 0:
                detail.append((ci,ri,'missing',False,'invalid length'))
                continue
            total += 1
            matched=[]
            for lay in layouts():
                got = lay.get(call['state_entry'])
                if not got: continue
                S,i,j = got
                stream,S2,i2,j2 = rc4_prga_bytes(S,i,j,n)
                out_match = stream == call['out_return'][:n]
                state_match = True
                if call.get('state_return'):
                    predicted = lay.put(S2,i2,j2,call['state_entry'])
                    state_match = predicted[:min(len(predicted),len(call['state_return']))] == call['state_return'][:min(len(predicted),len(call['state_return']))]
                if out_match:
                    matched.append(lay.name + ('+state' if state_match else '+out_only'))
            good=bool(matched)
            if good: ok += 1
            detail.append((ci,ri,call.get('len'),good, ','.join(matched) if matched else 'no layout matched'))
    return ok,total,detail


def validate_ksa_links(cycles):
    total=0; ok=0; detail=[]
    for ci,c in enumerate(cycles,1):
        # link each rc4_key event to the next rc4 entry in the same cycle by line order.
        rc4_entries=[r for r in c['rc4'] if 'state_entry' in r]
        for ki,k in enumerate(c['keys'],1):
            if 'keybuf' not in k or 'len' not in k:
                detail.append((ci,ki,'missing',False,'missing keybuf/len'))
                continue
            next_entries=[r for r in rc4_entries if r.get('entry_line',0) > k.get('entry_line',0)]
            if not next_entries:
                detail.append((ci,ki,k.get('len'),False,'no following rc4 entry'))
                continue
            nxt=next_entries[0]
            n=int(k.get('len') or 0)
            if n <= 0:
                detail.append((ci,ki,k.get('len'),False,'invalid key length'))
                continue
            key=k['keybuf'][:n]
            total += 1
            matched=[]
            for lay in layouts():
                S,i,j=ksa_bytes(key)
                # construct from next entry as template so bytes outside known fields are preserved for comparison window
                pred=lay.put(S,i,j,nxt['state_entry'])
                cmp_len=min(len(pred),len(nxt['state_entry']))
                if pred[:cmp_len] == nxt['state_entry'][:cmp_len]:
                    matched.append(lay.name)
            good=bool(matched)
            if good: ok += 1
            detail.append((ci,ki,n,good, ','.join(matched) if matched else 'no layout matched next rc4 state'))
    return ok,total,detail


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('jsonl')
    args=ap.parse_args()
    cycles=build_cycles(load_events(args.jsonl))

    tok,trows=validate_transport(cycles)
    print('cycle entry vlh rc4_calls rc4_key_calls transport_match status')
    for i,line,vlh,rc4n,keyn,match in trows:
        print(f'{i:02d} {line} {vlh} {rc4n} {keyn} {match} {"PASS" if match else "FAIL"}')
    print(f'V24_CLOSEG transport PASS={tok}/{len(cycles)}')

    pok,ptotal,pdetail=validate_prga(cycles)
    print('\n[RC4 PRGA REPLAY]')
    for ci,ri,n,good,msg in pdetail:
        print(f'cycle={ci:02d} rc4_call={ri:02d} len={n} status={"PASS" if good else "FAIL"} layout={msg}')
    print(f'V24_CLOSEG rc4_prga PASS={pok}/{ptotal}')

    kok,ktotal,kdetail=validate_ksa_links(cycles)
    print('\n[RC4 KEY/KSA LINKS]')
    for ci,ki,n,good,msg in kdetail:
        print(f'cycle={ci:02d} rc4_key={ki:02d} keylen={n} status={"PASS" if good else "FAIL"} layout={msg}')
    print(f'V24_CLOSEG rc4_key PASS={kok}/{ktotal}')

    if len(cycles) and tok == len(cycles) and ptotal and pok == ptotal and (ktotal == 0 or kok == ktotal):
        print('\nOVERALL=PASS_WITH_CAVEAT')
        print('Caveat: if no rc4_key links were captured, this closes PRGA+transport only, not the full KSA boundary.')
    else:
        print('\nOVERALL=INCOMPLETE')

if __name__ == '__main__':
    main()
