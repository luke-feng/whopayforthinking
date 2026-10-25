"""Offline replay of the published results. Never submits jobs or executes candidates."""
from pathlib import Path
from collections import Counter
from fractions import Fraction as F
import argparse
import hashlib
import json
import math
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
MEASURE=ROOT/'code/measurement/scripts/calibration'
ANALYSIS=ROOT/'analysis'
sys.path.insert(0,str(MEASURE));sys.path.insert(0,str(ANALYSIS))
# Version control and locally generated outputs are not part of the file manifest.
UNTRACKED_PARTS={'.git','reproduced','__pycache__'}
UNTRACKED_NAMES={'.DS_Store'}

def read(p,**kwargs):return json.loads(Path(p).read_text(),**kwargs)
def check(ok,why):
    if not ok:raise ValueError(why)
def close(a,b,why):check(math.isclose(float(a),float(b),rel_tol=1e-12,abs_tol=1e-9),why)

def tracked(p):
    rel=p.relative_to(ROOT)
    return not (UNTRACKED_PARTS&set(rel.parts) or p.name in UNTRACKED_NAMES or rel.parts[:2]==('analysis','output'))

def integrity():
    entries=read(ROOT/'manifests/files.json')
    names={x['path'] for x in entries}
    actual={str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_file() and tracked(p)}
    check(actual==names|{'manifests/files.json','SHA256SUMS'},'Unexpected or missing package files')
    check(not any(p.is_symlink() for p in ROOT.rglob('*') if tracked(p)),'Symlinks are not part of this package')
    for x in entries:
        p=(ROOT/x['path']).resolve()
        check(ROOT in p.parents,'Unsafe manifest path')
        raw=p.read_bytes()
        check(len(raw)==x['bytes'] and hashlib.sha256(raw).hexdigest()==x['sha256'],'Package checksum: '+x['path'])
    return len(entries)

def replay_records():
    import lcb_ngpu_lean_analysis as analysis
    import bootstrap_pairs
    import retail_result_tables as retail
    rows=read(ROOT/'manifests/raw-coverage.json')['cells']
    boot={x['id']:x for x in read(ANALYSIS/'evidence/bootstrap-inputs.json')['cells']}
    roster=read(ROOT/'code/measurement/data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json')['main_task_ids']
    follow=read(ANALYSIS/'evidence/service-followup-provenance.json')
    key=lambda x:(x['stratum'],x['config'],x['k'],x['replicate'])
    resource={'service':{key(x):x for x in follow['service_cells']},
              'a100':{key(x):x for x in follow['a100_cells']}}
    retail_data=retail.Data()
    counts=Counter();n_candidates=0;exact_prompt_fields=0;metric_checks=0
    for row in rows:
        raw_path=ROOT/row['extract_exports'][0]
        raw=read(raw_path);m=analysis.cell_metrics(raw)
        check(m['status']=='complete','Incomplete published cell: '+row['cell_id'])
        check(m['tasks']==106,'Task coverage')
        cp=ROOT/sorted(row['collect_exports'],key=lambda x:(not x.endswith('-collect.json'),x))[0]
        collect=read(cp)
        c=next(x for x in collect['cells'] if x['cell_id']==raw['cell_id'])
        check(c['status'].startswith('measured'),'Collected cell not measured')
        counts[row['cohort']]+=1;n_candidates+=len(raw['candidates'])
        if row['cohort']=='pipeline':
            expected=boot[row['cell_id']]
            columns=bootstrap_pairs.prompt_columns(read(raw_path,parse_float=str),roster)
            check(columns==expected['columns'],'Frozen per-task sufficient statistics: '+row['cell_id'])
            exact_prompt_fields+=sum(len(v) for v in columns.values())
            check(c['gpu_step_occupancy_ns']==expected['gpu_window_ns'],'Pipeline GPU counter')
            check(c['cpu_point_usec']==expected['cpu_usec'],'Pipeline CPU counter')
            check(raw['service_wall_ns']==expected['service_wall_ns'],'Pipeline service wall')
            metric_checks+=3
        else:
            rep=raw['replicate_id']
            rep=rep if isinstance(rep,str) and rep.startswith('r') else 'r'+str(rep)
            k=(raw['stratum_id'],raw['config_id'],raw['k'],rep)
            expected=resource[row['cohort']][k]
            check(c['gpu_step_occupancy_ns']==expected['gpu_step_occupancy_ns'],'Follow-up GPU counter')
            check(c['cpu_point_usec']==expected['cpu_point_usec'],'Follow-up CPU counter')
            close(m['generation_span_s'],F(expected['generation_span_s_exact']),'Generation span')
            metric_checks+=3
            if row['cohort']=='service':
                r=retail_data.cell(k[0],k[1],k[2],int(k[3][1:]))
                check(round(m['q_plus']*106)==r['qplus_count'],'Correct deliveries')
                check(round(m['q_minus']*106)==r['qminus_count'],'Incorrect deliveries')
                close(m['billed_input_tokens'],r['tokens']['input'],'Input tokens')
                close(m['delivered_output_tokens'],r['tokens']['delivered'],'Delivered tokens')
                close(m['H_all_non_delivered'],r['tokens']['hidden_all'],'Hidden tokens')
                close(m['reasoning_tokens_all'],r['tokens']['reasoning'],'Reasoning tokens')
                close(m['tau_delivery_s']/3600,r['tau'],'Delivery latency')
                close(m['service_window_s'],F(expected['service_window_s_exact']),'Service window')
                close(m['service_cpu_s']*1e6,expected['service_cpu_usec'],'Service CPU')
                close(m['service_cpu_startup_s']*1e6,expected['service_cpu_startup_usec'],'Startup-inclusive CPU')
                metric_checks+=10
    check(dict(counts)=={'pipeline':72,'service':66,'a100':15},'Cohort coverage')
    return {'cells':dict(counts),'candidates':n_candidates,'exact_per_task_fields':exact_prompt_fields,'additional_metric_checks':metric_checks,'new_estimates':False}

def analysis_results():
    import result_evidence,make_result_tables,retail_result_figures
    result=result_evidence.verify()
    for name,text in make_result_tables.render_files().items():
        check((ANALYSIS/'tables'/name).read_text()==text,'Generated numerical table: '+name)
    for name,text in retail_result_figures.render()[0].items():
        check((ANALYSIS/'figures/src'/name).read_text()==text,'Generated plot source: '+name)
    return {'evidence':'passed','tables':'passed','plot_data':'passed','retail_contract_profiles':result['retail_pricing']['reference_contract_profiles']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-file-check',action='store_true',help='Only for rebuilding the file manifest')
    parser.add_argument('--theory',action='store_true',help='Also run the exact synthetic theory checks')
    args=parser.parse_args()
    result={'package_files_verified':None if args.skip_file_check else integrity(),'records':replay_records(),'analysis':analysis_results(),'cluster_commands':False,'candidate_code_executed':False}
    if args.theory:
        for name in ['check_generalizations.py','check_retail_theory.py']:
            proc=subprocess.run([sys.executable,'-I','-B','-c',"import runpy,sys;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name='__main__')",str(ANALYSIS),str(ANALYSIS/name)],capture_output=True,text=True,check=True)
            result[name]=json.loads(proc.stdout)['status']
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
