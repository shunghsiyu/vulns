import json, re, csv, sys, collections, os
S=os.path.dirname(os.path.abspath(__file__))
rows=json.load(open(f'{S}/bpf_raw.json'))
try: OV=json.load(open(f'{S}/overrides.json'))
except FileNotFoundError: OV={}
SHIPPED_ARCH={'x86','arm64','powerpc','s390'}   # assumed distro arches (x86_64, aarch64, ppc64le, s390x)
EBPF_ONLY=re.compile(r'tail ?call|tailcall|trampoline|struct[_ ]?ops|kfunc|atomic|arena|exception|probe_mem|sdiv|smod|sign[- ]?ext|movsx|ldsx|subprog|poke|fentry|freplace|may_goto|load[-_]acquire|per-?cpu|extable|private stack|kprobe|bti|128-bit|cfi|bpf2bpf|callback|signed alu32|text_poke|kasan', re.I)
def files_of(x): return [f for f in x['files'].split(';') if f]
def arch_of(f):
    m=re.match(r'arch/([^/]+)/',f); return m.group(1) if m else None
def classify(x):
    t=x['title']; tl=t.lower(); b=x['body'].lower(); fs=files_of(x)
    kfs=[f for f in fs if not f.startswith(('tools/','samples/','Documentation/'))]
    o={}
    # ---- flavor
    if not kfs or all(f=='lib/test_bpf.c' for f in kfs): flavor='tools'
    elif 'seccomp' in tl or 'cbpf' in tl or 'classic bpf' in tl: flavor='cBPF'
    elif any(f.startswith('net/xdp/') for f in kfs) or tl.startswith('xsk'): flavor='AF_XDP'
    elif any(arch_of(f) for f in kfs) and all(arch_of(f) or f.startswith('include/') for f in kfs): flavor='JIT'
    else: flavor='eBPF'
    archs={arch_of(f) for f in kfs if arch_of(f)}
    # ---- area (alternative scheme)
    VER=('kernel/bpf/verifier.c','kernel/bpf/states.c','kernel/bpf/backtrack.c','kernel/bpf/cfg.c','kernel/bpf/fixups.c','kernel/bpf/log.c','kernel/bpf/tnum.c','kernel/bpf/disasm.c','include/linux/bpf_verifier.h')
    IFC=('kernel/bpf/syscall.c','kernel/bpf/inode.c','kernel/bpf/token.c','kernel/bpf/offload.c','kernel/bpf/net_namespace.c','kernel/bpf/mprog.c','kernel/bpf/bpf_iter.c','kernel/bpf/map_iter.c','kernel/bpf/map_in_map.c','net/bpf/test_run.c','include/linux/bpfptr.h','include/uapi/linux/bpf.h','include/linux/bpf_types.h','kernel/bpf/btf.c','net/bpf/bpf_dummy_struct_ops.c')
    MAPS=('kernel/bpf/hashtab.c','kernel/bpf/arraymap.c','kernel/bpf/lpm_trie.c','kernel/bpf/bloom_filter.c','kernel/bpf/queue_stack_maps.c','kernel/bpf/local_storage.c','kernel/bpf/percpu_freelist','kernel/bpf/bpf_lru_list','kernel/bpf/memalloc.c')
    if flavor=='tools': area='n/a(tools)'
    elif flavor=='JIT' or (any(f=='kernel/bpf/core.c' for f in kfs) and re.search(r'interpreter|jit|blind|ksym|lock_ro',tl)): area='unplaced(JIT/interp)'
    elif 'verifier' in tl or any(f in VER for f in kfs): area='verifier'
    elif any(f in IFC for f in kfs) or re.search(r'\blink\b|syscall|bpffs|fdinfo|prog_query|link_create',tl):
        area='interface'
        if any(f=='kernel/bpf/btf.c' for f in kfs) and re.search(r'raw_tp|nullable|sleepable|scalar|argument',tl): area='verifier'
    elif any(f.startswith(MAPS) for f in kfs) or re.search(r'\bmap\b|hashmap|htab',tl) and not re.search(r'sockmap|devmap|cpumap|xskmap|sock_map',tl): area='unplaced(maps)'
    else: area='cross-subsystem'
    # ---- reachability under distro defaults
    if flavor=='tools': reach='none'; why='userspace tools/samples/selftests only'
    elif flavor=='JIT' and archs and not (archs & SHIPPED_ARCH): reach='none'; why='JIT for non-shipped arch: '+','.join(sorted(archs))
    elif ('32-bit' in tl or '32bit' in tl) and 'arches' in tl or 'on 32-bit kernels' in tl: reach='none'; why='32-bit only'
    elif 'cfi' in tl and 'clang' in tl: reach='cap_bpf'; why='CFI config only'
    elif flavor=='cBPF': reach='unpriv'; why='cBPF/seccomp reachable without privileges'
    elif flavor=='AF_XDP': reach='unpriv_userns'; why='AF_XDP socket needs only CAP_NET_RAW in a user namespace'
    elif flavor=='JIT':
        if EBPF_ONLY.search(tl) or EBPF_ONLY.search(b[:1500]): reach='cap_bpf'; why='JIT path for eBPF-only feature'
        else: reach='unpriv?'; why='JIT path possibly shared with cBPF (SO_ATTACH_FILTER/seccomp are JITed)'
    elif area=='verifier' and re.search(r'(pointer|address|ptr)[- ]?leak|speculat|nospec|spectre',tl): reach='none'; why='verifier check that only constrains unprivileged loaders (allow_ptr_leaks/bypass_spec); moot with unprivileged BPF off'
    elif area=='verifier' or area=='interface': reach='cap_bpf'; why='needs bpf() prog/map load (CAP_BPF)'
    elif re.search(r'sockmap|skmsg|sk_msg|sock_map|tcp_bpf|udp_bpf|unix_bpf|psock|ktls|msg_(pop|push)_data',tl+' '+x['files']) : reach='deployed'; why='sockmap/skmsg datapath: traffic from unprivileged/remote peers once a sockmap program is deployed'
    elif re.search(r'devmap|cpumap|xdp|redirect|netkit|tcx|cls_bpf|act_bpf|lwt|seg6|skb_|gso|sk_assign|reuseport|syncookie|tunnel|dst|sk_lookup|tls',tl) : reach='deployed'; why='packet datapath: remote/unprivileged traffic once an XDP/tc program is deployed'
    elif re.search(r'cgroup|lsm|sysctl|sockopt',tl) or any(f in ('kernel/bpf/cgroup.c','kernel/bpf/bpf_lsm.c') for f in kfs): reach='deployed'; why='cgroup/LSM hook run on unprivileged syscalls once a program is attached (e.g. systemd)'
    else: reach='cap_bpf'; why='needs attacker-loaded program or bpf() (CAP_BPF)'
    if 'preempt_rt' in tl or 'preempt_rt' in b[:600]: why+='; PREEMPT_RT only'
    # ---- effect
    s=tl+' '+b[:2500]
    if re.search(r'use-after-free|\buaf\b|out-of-bounds write|oob write|double free|double sock release|stack corruption|heap overflow|buffer overflow|arbitrary (read|write)|type confusion|refcount underflow|corrupt',s): eff='memory-corruption'
    elif area=='verifier' and re.search(r'unsound|incorrect pruning|precision|bounds|range|pointer|out-of-bounds|oob|spill|regsafe|leak|track|nullable|null|invalidate|reject|id\b',s) and not re.search(r'memory leak|memleak|kmemleak|warn|lockdep|splat',tl): eff='verifier-bypass'
    elif re.search(r'out-of-bounds|\boob\b|overrun|overflow',s): eff='memory-corruption'
    elif re.search(r'(address|pointer|info(rmation)?) leak|leak(s|ing)? (kernel|uninit|stack|pointer)|uninit(ialized)? (value|memory|data)|kernel address',s): eff='info-leak'
    elif re.search(r'memory leak|memleak|kmemleak|reference count leak|refcount leak|\bleak\b',tl): eff='minor(leak)'
    elif re.search(r'warn|lockdep|splat|kcsan|kmsan|data-race|invalid wait context|silence',tl): eff='minor(warn)'
    elif re.search(r'null|panic|crash|oops|bug\b|deadlock|lockup|stall|infinite loop|recursi|hang|div(ide)? by zero|general protection',s): eff='crash/DoS'
    elif re.search(r'permission|bypass|lockdown|mitigat|spectre|bhb|harden|spray',s): eff='security-policy'
    else: eff='other/functional'
    if eff in ('other/functional','minor(leak)') and re.search(r'/[CIA]:H',x['vector']): eff='severe(per CNA C/I/A)'
    o=dict(flavor=flavor, area=area, reach=reach, reach_note=why, effect=eff)
    o.update(OV.get(x['cve'],{}))
    # ---- buckets
    r=o['reach']; e=o['effect']
    severe = e in ('memory-corruption','verifier-bypass','info-leak','crash/DoS','security-policy','severe(per CNA C/I/A)')
    if r=='none': impact='none'
    elif r in ('unpriv','unpriv_userns','unpriv?') and severe: impact='HIGH'
    elif r=='deployed' and severe: impact='HIGH-if-deployed'
    elif r=='cap_bpf' and e in ('memory-corruption','verifier-bypass','severe(per CNA C/I/A)'): impact='LOW(root->kernel)'
    elif severe: impact='LOW'
    else: impact='MINIMAL'
    o['impact_est']=impact
    # proposal
    if r=='none': prop='1-blocklist'
    elif o['flavor']=='cBPF': prop='3-CVE(cBPF)'
    else: prop='2-git-fix'
    o['proposal']=prop
    return o
out=[]
for x in sorted(rows,key=lambda x:x['cve']):
    c=classify(x)
    out.append(dict(cve=x['cve'], title=x['title'], cna_cvss=x['cvss'], cna_vector=x['vector'].replace('CVSS:3.1/',''), **c, files=x['files']))
json.dump(out,open(f'{S}/classified.json','w'))
if '-q' not in sys.argv:
    C=collections.Counter
    print(C(o['flavor'] for o in out)); print(C(o['area'] for o in out)); print(C(o['reach'] for o in out)); print(C(o['effect'] for o in out)); print(C(o['impact_est'] for o in out))
