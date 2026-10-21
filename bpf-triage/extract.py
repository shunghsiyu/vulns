import json, glob, os, re, sys, csv
import os; HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.join(HERE,'..','cve','published')
BPF_RE = re.compile(r'^(kernel/bpf/|net/core/(filter|skmsg|sock_map|xdp|bpf_sk_storage)\.c|net/ipv4/(tcp|udp)_bpf\.c|net/unix/unix_bpf\.c|net/ipv4/bpf_tcp_ca\.c|net/bpf/|net/sched/(cls|act)_bpf\.c|net/netfilter/xt_bpf\.c|net/xdp/|kernel/trace/bpf_trace\.c|arch/[^/]+/net/|include/linux/(bpf|btf|filter|skmsg|tnum)|include/uapi/linux/(bpf|btf|filter)|include/net/(xdp|tcx|netkit)|lib/test_bpf\.c|drivers/net/netkit\.c|tools/lib/bpf/|tools/bpf/|tools/testing/selftests/bpf/|samples/bpf/|crypto/bpf_crypto|kernel/bpf|mm/bpf_)')
rows=[]
for y in sorted(os.listdir(ROOT)):
    for f in glob.glob(f'{ROOT}/{y}/*.json'):
        d=json.load(open(f))
        c=d['containers']['cna']
        files=sorted({p for a in c.get('affected',[]) for p in a.get('programFiles',[])})
        desc=c['descriptions'][0]['value']
        body=desc.split('resolved:\n\n',1)[-1]
        title=body.split('\n',1)[0].strip()
        bpf_files=[p for p in files if BPF_RE.match(p)]
        tl=title.lower()
        subj_bpf = bool(re.match(r'^(bpf|xdp|xsk|libbpf|bpftool|selftests/bpf|sock_?map|skmsg|tcp_bpf|udp_bpf|net/sched: (cls|act)_bpf|seccomp)\b', tl)) or re.match(r'^[^:]*\bbpf\b[^:]*:', tl)
        if not bpf_files and not subj_bpf: continue
        cvss=''; vec=''
        for m in c.get('metrics',[]):
            if 'cvssV3_1' in m: cvss=m['cvssV3_1']['baseScore']; vec=m['cvssV3_1']['vectorString']
        rows.append(dict(cve=d['cveMetadata']['cveId'], title=title, files=';'.join(files), bpf_files=';'.join(bpf_files),
                         cvss=cvss, vector=vec, body=body))
print(len(rows), file=sys.stderr)
json.dump(rows, open(os.path.join(HERE,'bpf_raw.json'),'w'))
