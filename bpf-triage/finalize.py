import json,collections,csv,os
S=os.path.dirname(os.path.abspath(__file__))
o=json.load(open(f'{S}/classified.json')); samp=json.load(open(f'{S}/sample.json'))
AREA_POLICY={'verifier':'git-fix','interface':'git-fix','cross-subsystem':'CVE','unplaced(JIT/interp)':'undefined','unplaced(maps)':'undefined','n/a(tools)':'blocklist'}
for x in o:
    i=x['impact_est']; p=x['proposal']
    x['proposal_verdict']= ('MISS: high impact sent to '+p) if i=='HIGH' and p!='3-CVE(cBPF)' else ('MISS-if-deployed: sent to '+p) if i=='HIGH-if-deployed' else ('OVER: minor kept in CVE process') if p=='3-CVE(cBPF)' and i in('MINIMAL','LOW','none') else 'ok'
    ap=AREA_POLICY[x['area']]; x['area_policy_assumed']=ap
    x['area_verdict']= 'NO AREA: needs a rule' if ap=='undefined' else ('MISS: high impact sent to git-fix' if ap=='git-fix' and i=='HIGH' else 'MISS-if-deployed' if ap=='git-fix' and i=='HIGH-if-deployed' else 'OVER: low impact kept in CVE process' if ap=='CVE' and i in ('LOW','MINIMAL','LOW(root->kernel)','none') else 'ok')
    x['sample_trigger_check']=samp.get(x['cve'],'')
C=collections.Counter
print(C((x['proposal'],x['impact_est']) for x in o))
print(C(x['proposal_verdict'] for x in o)); print(C(x['area_verdict'] for x in o))
for a in sorted({x['area'] for x in o}): print(a, dict(C(x['impact_est'] for x in o if x['area']==a)), 'n=',sum(x['area']==a for x in o))
print('HIGH by flavor', C(x['flavor'] for x in o if x['impact_est']=='HIGH'))
print('verifier CNA', C(x['cna_vector'].split('/')[2] for x in o if x['area']=='verifier' and x['cna_vector']), sum(1 for x in o if x['area']=='verifier' and x['cna_vector']))
cols=['cve','title','flavor','area','proposal','reach','reach_note','effect','impact_est','proposal_verdict','area_policy_assumed','area_verdict','sample_trigger_check','cna_cvss','cna_vector','files']

with open(f'{S}/bpf_cve_triage.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=cols,extrasaction='ignore'); w.writeheader()
    order={'HIGH':0,'HIGH-if-deployed':1,'LOW(root->kernel)':2,'LOW':3,'MINIMAL':4,'none':5}
    for x in sorted(o,key=lambda x:(order[x['impact_est']],x['cve'])): w.writerow(x)
print('rows',len(o))
