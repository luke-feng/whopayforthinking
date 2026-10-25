"""Closed v3 owner wrapper and pure supervision replay model.

prepare archives metadata; replay validates simulated/recorded observations only.
run is deliberately unavailable. Cancellation intents are data, never executed.
No legacy sandbox, native helper, srun, scancel, or candidate is invoked.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

# Support isolated Python (-I) without accepting PYTHONPATH module substitution.
sys.path.insert(0,str(Path(__file__).resolve().parent))
import lcb_slurm_readonly_v3 as readonly

ROOT=Path(__file__).resolve().parents[2]
PLAN='experiments/calibration/supervision-v3-acceptance.json'
PLAN_SHA='c928668859f85275bbfa732b5aca8db709f39d6f5452db7f9a9ed06e41ece700'
FILES=('scripts/calibration/lcb_supervisor_v3.py','scripts/calibration/lcb_slurm_readonly_v3.py',PLAN,readonly.DECISION)
GATES=('implementation_approved','trusted_probe_authorized','candidate_execution_authorized','main_matrix_authorized','site_recovery_verified')
SCENARIOS=('scheduler-normal','permission-normal','controller-loss','master-loss','escaped-session','supervisor-loss','nproc-boundary','isolation-metering')
TERMINAL=('COMPLETED','CANCELLED','FAILED','TIMEOUT','OUT_OF_MEMORY','NODE_FAIL','PREEMPTED','DEADLINE')

def check(ok,msg):
    if not ok:raise ValueError(msg)

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def absolute(path,exists=True):
    p=Path(path);check(p.is_absolute() and '..' not in p.parts and not any(x.is_symlink() for x in (p,*p.parents)),
                       'Canonical absolute non-symlink path required')
    return p.resolve(strict=exists)

def write(path,value):
    with Path(path).open('x') as stream:json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')

def plan():
    check(Path(readonly.__file__).resolve()==Path(__file__).resolve().with_name('lcb_slurm_readonly_v3.py'),'Wrong read-only dependency module')
    raw=(ROOT/PLAN).read_bytes();check(hashlib.sha256(raw).hexdigest()==PLAN_SHA,'Acceptance plan bytes changed')
    value=readonly.strict(raw)
    check(sha(ROOT/readonly.DECISION)==readonly.DECISION_SHA and value['decision_sha256']==readonly.DECISION_SHA,'Wrong v3 decision')
    check(tuple(s['id'] for s in value['scenarios'])==SCENARIOS,'Unexpected acceptance scenarios')
    check(value['local_domain']=={'production_tasks':32,'production_reserved_tasks':2,'candidate_tasks':30,'permission_only_nproc':8},'Local task budget changed')
    s=value['supervision'];t=value['timing_policy'];budget=t['observation_sizing']
    check(s['step_recovery_observation_s']==s['job_recovery_observation_s']==sum(budget.values()),'Observation budget differs')
    case_budget=s['case_observation_s']+s['normal_checkpoint_allowance_s']
    check(s['case_observation_s']==30 and s['normal_checkpoint_allowance_s']==5,'Separate case/checkpoint budgets required')
    reserve=case_budget+s['step_recovery_observation_s']+s['job_recovery_observation_s']+t['final_evidence_allowance_s']
    total=t['setup_planning_allowance_s']+value['maximum_cases_per_worker']*case_budget+reserve-case_budget
    check(t['minimum_remaining_at_case_start_s']==reserve and
          total==t['bounded_work_and_observation_planning_total_s']<=value['worker_resources']['job_walltime_s'],
          'Worker observation reserve does not fit')
    check(t['finite_cleanup_upper_bound_s'] is None and
          t['external_observer_required_after_job_request_or_supervisor_loss'] is True,'Observation is not a cleanup guarantee')
    check(all(value[k] is False for k in ('native_fixture_implementation_registered','live_transport_implemented','site_tracking_verified','site_recovery_verified','implementation_approved','owner_probe_approved','trusted_probe_authorized','candidate_execution_authorized','main_matrix_authorized')),'This package cannot grant release')
    return value

def timing_check(screening,spec):
    t=spec['timing_policy']
    check(screening.get('interpretation_policy')=='slurm-timeout-semantics-v1' and
          screening.get('semantic_version_reviewed') is True,'Corrected timeout interpretation required')
    check(screening['screening']=='configuration_reported_compatible_pending_trusted_acceptance' and
          screening['selected_fields']['ClusterName']==t['required_cluster'] and
          screening['client_version']==t['required_version'],'Site/version differs from reviewed timing policy')
    for key,seconds in t['required_seconds'].items():
        row=screening['timeout_values'][key]
        check(row['state']=='finite' and type(row['seconds']) is int and row['seconds']==seconds,
              'Site timer differs or is unidentified: '+key)
    check(screening['prolog_epilog_layout'] in ('combined','split') and
          all(v['state'] in ('finite','zero','default_unlimited') for v in screening['effective_script_timeouts'].values()),
          'Prolog/epilog timeout layout unresolved')

def timing(draft):
    spec=plan();check(draft.get('fixed_plan')==spec,'Draft must bind current timing plan')
    timing_check(draft['screening'],spec)
    return spec

def fixed_recovery_windows(draft):
    """Guard the live adapters' 360-second constants against a changed plan.

    A timing-policy change must update all adapters under a separate review.
    This is a consistency assertion, not permission to invoke any adapter.
    """
    supervision=timing(draft)['supervision']
    check(all(type(supervision[k]) is int and supervision[k]==360 for k in
              ('step_recovery_observation_s','job_recovery_observation_s')),
          'Live adapter recovery windows differ from the registered 360-second policy')

def source_identity():
    def git(*args):return subprocess.run(['git','-C',str(ROOT),*args],check=True,capture_output=True,timeout=30).stdout
    head=git('rev-parse','HEAD').decode().strip();check(re.fullmatch('[0-9a-f]{40}',head),'Invalid source HEAD')
    check(not git('status','--porcelain','--untracked-files=all','--ignored'),'Clean tool checkout required')
    hashes={}
    for name in FILES:
        p=absolute(ROOT/name);body=p.read_bytes()
        check(git('show',head+':'+name)==body,'Code/plan not tracked at selected HEAD')
        hashes[name]=hashlib.sha256(body).hexdigest()
    return {'head':head,'files_sha256':hashes,'status_porcelain':''}

def prepare(*,inventory,output,scenario):
    check(scenario in SCENARIOS,'Unknown fixed scenario');spec=plan();source=source_identity()
    check(os.getuid()>0,'Non-root owner required')
    inp=absolute(inventory);value=readonly.read(inp);screening=readonly.interpret(value)
    timing_check(screening,spec)
    root=absolute(output,False)
    check(not root.exists() and root.parent.is_dir() and root.name.startswith('www27-supervision-v3.'),'Fresh v3 output directory required')
    check(ROOT not in root.parents and root!=ROOT and inp not in root.parents and root!=inp,'Output overlaps input/source')
    nonce=secrets.token_hex(16);raw=inp.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    check(readonly.strict(raw)==value,'Inventory changed during preparation')
    root.mkdir(mode=0o700)
    with (root/'slurm-inventory.json').open('xb') as stream:stream.write(raw)
    draft={'schema':'supervision-v3-draft','purpose':'targeted_trusted_acceptance_design_only','source':source,
           'scenario':scenario,'attempt_nonce':nonce,'expected_job_name':'www27-v3-'+nonce[:12],
           'expected_job_comment':'www27-attempt:'+nonce,'owner_uid':os.getuid(),
           'inventory_sha256':digest,'screening':screening,'plan_sha256':sha(ROOT/PLAN),
           'fixed_plan':spec,'runtime_bindings':None,'live_transport_bound':False,
           'owner_approved':False,**dict.fromkeys(GATES,False)}
    check(source_identity()==source and sha(inp)==digest,'Source/input changed before draft completion')
    write(root/'draft.json',draft);write(root/'draft.sha256.json',{'sha256':sha(root/'draft.json')})
    return draft

def load_draft(root):
    root=absolute(root);value=readonly.read(root/'draft.json')
    check(readonly.read(root/'draft.sha256.json')=={'sha256':sha(root/'draft.json')},'Draft changed')
    check(value['schema']=='supervision-v3-draft' and value['purpose']=='targeted_trusted_acceptance_design_only','Wrong draft')
    check(value['fixed_plan']==plan() and value['plan_sha256']==sha(ROOT/PLAN),'Plan changed')
    check(value['source']['files_sha256']=={n:sha(ROOT/n) for n in FILES},'Wrong code snapshot')
    check(re.fullmatch('[0-9a-f]{40}',value['source']['head']) and value['source']['status_porcelain']=='','Invalid source state')
    check(sha(root/'slurm-inventory.json')==value['inventory_sha256'],'Inventory original changed')
    check(readonly.interpret(readonly.read(root/'slurm-inventory.json'))==value['screening'],'Screening differs')
    timing_check(value['screening'],value['fixed_plan'])
    check(value['scenario'] in SCENARIOS and re.fullmatch('[0-9a-f]{32}',value['attempt_nonce']),'Bad scenario/nonce')
    check(value['expected_job_name']=='www27-v3-'+value['attempt_nonce'][:12] and
          value['expected_job_comment']=='www27-attempt:'+value['attempt_nonce'],'Draft job labels differ')
    check(type(value['owner_uid']) is int and value['owner_uid']>0,'Non-root owner required')
    check(value['runtime_bindings'] is None and value['live_transport_bound'] is False and value['owner_approved'] is False and
          all(value[g] is False for g in GATES),'Draft cannot grant live permission')
    return value

def group(value,job_id,step_id=None):
    check(isinstance(value,dict) and set(value)=={'path','device','inode'},'Full resource identity required')
    check(all(type(value[k]) is int and value[k]>0 for k in ('device','inode')),'Invalid resource object')
    path=value['path'];check(isinstance(path,str) and path.startswith('/sys/fs/cgroup/') and
                           str(Path(path))==path and '..' not in Path(path).parts and
                           not any(ord(c)<32 for c in path) and '/job_'+job_id+'/' in path+'/','Wrong job cgroup')
    if step_id is not None:check('/step_'+step_id+'/' in path+'/','Wrong step cgroup')

def lease_check(draft,lease):
    timing(draft)
    expected={'cluster','job_id','step_id','uid','node','node_boot_id','submit_time','job_name','job_comment','attempt_nonce',
              'source_sha','job_cgroup','step_cgroup','dedicated_cpu_worker'}
    check(isinstance(lease,dict) and set(lease)==expected,'Unexpected lease fields')
    for key in ('cluster','node'):check(isinstance(lease[key],str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',lease[key]),'Invalid cluster/node')
    check(isinstance(lease['node_boot_id'],str) and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',lease['node_boot_id']),'Invalid node boot identity')
    check(isinstance(lease['job_id'],str) and re.fullmatch('[1-9][0-9]{0,9}',lease['job_id']),'Single numeric job required')
    check(isinstance(lease['step_id'],str) and re.fullmatch('0|[1-9][0-9]{0,8}',lease['step_id']),'Numeric execution step required')
    check(type(lease['uid']) is int and lease['uid']==draft['owner_uid']>0,'Wrong owner UID')
    check(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',lease['submit_time']),'Explicit UTC submit time required')
    datetime.strptime(lease['submit_time'],'%Y-%m-%dT%H:%M:%S')
    check(lease['attempt_nonce']==draft['attempt_nonce'] and lease['source_sha']==draft['source']['head'] and
          lease['job_name']==draft['expected_job_name'] and lease['job_comment']==draft['expected_job_comment'] and
          lease['dedicated_cpu_worker'] is True,'Lease is not this dedicated attempt')
    group(lease['job_cgroup'],lease['job_id']);group(lease['step_cgroup'],lease['job_id'],lease['step_id'])
    check(lease['step_cgroup']['path'].startswith(lease['job_cgroup']['path'].rstrip('/')+'/'),'Step outside job domain')
    check((lease['step_cgroup']['device'],lease['step_cgroup']['inode'])!=(lease['job_cgroup']['device'],lease['job_cgroup']['inode']),'Job and step cannot be the same resource object')
    check(draft['screening']['screening']=='configuration_reported_compatible_pending_trusted_acceptance' and
          draft['screening']['selected_fields']['ClusterName']==lease['cluster'],'Cluster/config screening mismatch')

def observation_check(draft,lease,obs,now,scope):
    lease_check(draft,lease)
    spec=draft['fixed_plan']
    check(type(now) is int and now>0 and type(obs['observed_ns']) is int and
          0<=now-obs['observed_ns']<=spec['supervision']['fresh_observation_max_age_s']*1_000_000_000,'Stale/future observation')
    check(obs['node_boot_id']==lease['node_boot_id'],'Node reboot/clock domain changed')
    check(obs['observer_job_id']==lease['job_id'] and obs['observer_step']=='batch' and
          type(obs['observer_uid']) is int and obs['observer_uid']==lease['uid'],
          'Supervisor must belong to this job batch domain, not an external cancellation client')
    job=obs['job'];keys=('cluster','job_id','uid','node','submit_time','job_name','job_comment')
    check(all(job.get(k)==lease[k] and type(job.get(k)) is type(lease[k]) for k in keys),'Current job identity differs')
    check(job['cgroup']==lease['job_cgroup'] and job['state'] in ('RUNNING','COMPLETING'),'Job not active or resource identity changed')
    check(job['requeue'] is False and type(job['restarts']) is int and job['restarts']==0,'Requeued worker refused')
    check(type(job.get('time_limit_s')) is int and job['time_limit_s']==spec['worker_resources']['job_walltime_s'],
          'Finite frozen worker walltime required')
    check(type(job.get('time_remaining_s')) is int and 0<=job['time_remaining_s']<=job['time_limit_s'],
          'Observed worker remaining time required')
    allocation=job['allocation']
    check(all(type(allocation[k]) is int for k in ('logical_cpus','ram_bytes','gpu_count','nodes')) and
          allocation=={'logical_cpus':1,'ram_bytes':1073741824,'gpu_count':0,'nodes':1},'Not the frozen CPU-only allocation')
    hard=obs['hard_resources']
    check(set(hard)=={'logical_cpu_ids','memory_max_bytes','swap_max_bytes','scope_identity'} and
          hard['scope_identity']==lease['job_cgroup'] and isinstance(hard['logical_cpu_ids'],list) and
          len(hard['logical_cpu_ids'])==1 and type(hard['logical_cpu_ids'][0]) is int and hard['logical_cpu_ids'][0]>=0 and
          type(hard['memory_max_bytes']) is int and 0<hard['memory_max_bytes']<=1073741824 and
          (hard['swap_max_bytes'] is None or type(hard['swap_max_bytes']) is int and hard['swap_max_bytes']>=0),
          'Actual hard-resource observation missing or inconsistent; request strings are insufficient')
    step_ids=obs['step_ids'];check(isinstance(step_ids,list) and all(isinstance(x,str) for x in step_ids) and
          len(step_ids)==len(set(step_ids)) and set(step_ids)<={'batch','extern',lease['step_id']},'Shared/unexpected steps')
    check(obs['extern_user_tasks']==[],'Unexpected extern workload')
    step=obs.get('step')
    check((step is None)==(lease['step_id'] not in step_ids),'Step lookup and roster disagree')
    if scope=='step':
        check(step is not None and lease['step_id'] in step_ids,'Execution step missing')
    if step is not None:
        check(step['job_id']==lease['job_id'] and step['step_id']==lease['step_id'] and step['node']==lease['node'] and
              step['cgroup']==lease['step_cgroup'],'Step identity differs')
        if scope=='step':check(step['state'] in ('RUNNING','COMPLETING'),'Step is not active')

def cancellation_intent(draft,lease,obs,now,scope):
    check(scope in ('step','job'),'Invalid cancellation scope');observation_check(draft,lease,obs,now,scope)
    target=lease['job_id']+('.'+lease['step_id'] if scope=='step' else '')
    return {'scope':scope,'target':target,'argv':['scancel','--clusters='+lease['cluster'],target],
            'lease_sha256':canonical(lease),'observation_sha256':canonical(obs),'at_ns':now,
            'execution_authorized':False,'transport_implemented':False}

def replay(draft,lease,events):
    lease_check(draft,lease);check(isinstance(events,list) and len(events)<=128,'Bounded event stream required')
    spec=draft['fixed_plan'];s=spec['supervision']
    case_ns=s['case_observation_s']*1_000_000_000
    step_ns=s['step_recovery_observation_s']*1_000_000_000
    job_ns=s['job_recovery_observation_s']*1_000_000_000
    normal=draft.get('scenario')=='scheduler-normal'
    checkpoint_ns=s['normal_checkpoint_allowance_s']*1_000_000_000
    checkpoints=[];released_at=None
    state='idle';active=None;case_started=None;seen=set();last=0;actions=[];request_time=None;request_scope=None;request_result=None;outcomes=[]
    for index,event in enumerate(events,1):
        check(type(event['seq']) is int and event['seq']==index and type(event['ns']) is int and event['ns']>last,'Replayed/out-of-order event')
        now=event['ns'];last=now
        check(event['lease_sha256']==canonical(lease),'Cross-lease event')
        kind=event['type']
        check(state not in ('retired','recovery_unverified'),'Retired/unverified worker cannot continue')
        if kind=='case_start':
            check(state=='idle' and active is None,'Concurrent case or dispatch after failure')
            case=event['case_id'];check(isinstance(case,str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',case) and case not in seen and len(seen)<spec['maximum_cases_per_worker'],'Repeated/unbounded case')
            if normal:check(case=='normal-%02d'%(len(seen)+1),'Normal cases must follow the frozen order')
            observation_check(draft,lease,event['observation'],now,'step')
            # Deduct observation age conservatively; a fresh sample is not time-free.
            age_s=(now-event['observation']['observed_ns']+999_999_999)//1_000_000_000
            remaining=event['observation']['job']['time_remaining_s']-age_s
            check(remaining>=spec['timing_policy']['minimum_remaining_at_case_start_s'],
                  'Insufficient worker time for case and full observation reserve')
            seen.add(case);active=case;case_started=now;state='running'
        elif kind=='case_released':
            check(state=='running' and event['case_id']==active,'Wrong active case')
            check(now-case_started<=case_ns,'Normal release beyond observation deadline')
            proof=event['evidence'];required={'init_reaped','runner_reaped','known_pidfds_exited','case_outer_empty','identity_matches','no_pending_dispatch'}
            check(set(proof)==required and all(proof[k] is True for k in required),'Incomplete normal release assertion')
            outcomes.append({'case_id':active,'model_status':'released'})
            if normal:state='awaiting_checkpoint';released_at=now
            else:active=None;state='idle'
        elif kind=='normal_checkpoint':
            check(normal and state=='awaiting_checkpoint' and event['case_id']==active and active not in checkpoints,
                  'Wrong/replayed normal checkpoint')
            check(now-released_at<=checkpoint_ns and now-case_started<=case_ns+checkpoint_ns,'Normal checkpoint late')
            check(all(isinstance(event.get(k),str) and re.fullmatch('[0-9a-f]{64}',event[k]) for k in
                      ('worker_journal_sha256','closeout_sha256','authenticated_reply_sha256')),'Checkpoint anchors missing')
            checkpoints.append(active);active=None;state='idle'
        elif kind=='fault':
            check(state in ('idle','running','awaiting_checkpoint') and event['reason'] in ('controller_loss','master_loss','channel_eof','case_timeout','cleanup_timeout','unknown_residual'),'Unexpected fault')
            if event['reason']=='case_timeout':check(state=='running' and now-case_started>=case_ns,'Premature case timeout')
            state='failed';outcomes.append({'case_id':active,'model_status':'infrastructure_failure_not_candidate_wrong','reason':event['reason']})
        elif kind=='request_step_termination':
            check(state=='failed','Step request out of order');actions.append(cancellation_intent(draft,lease,event['observation'],now,'step'))
            state='waiting_step';request_time=now;request_scope='step';request_result=None
        elif kind=='request_result':
            check(state in ('waiting_step','waiting_job') and request_result is None and event['scope']==request_scope and type(event['accepted']) is bool,'Wrong/duplicate request result')
            check(now-request_time<=(job_ns if state=='waiting_job' else step_ns),'Request result past observation deadline')
            check(event['intent_sha256']==canonical(actions[-1]),'Request result belongs to another intent')
            request_result=event['accepted']  # Acceptance alone NEVER means cleanup.
        elif kind=='request_job_termination':
            check(state=='waiting_step' and request_result is True and now-request_time>=step_ns,'Premature/unaccepted/duplicate escalation')
            actions.append(cancellation_intent(draft,lease,event['observation'],now,'job'))
            state='waiting_job';request_time=now;request_scope='job';request_result=None
        elif kind=='recovery_evidence':
            check(state in ('waiting_step','waiting_job') and event['scope']==request_scope,'Wrong recovery scope')
            check(now-request_time<=(job_ns if state=='waiting_job' else step_ns),'Late cleanup requires separate reassessment')
            proof=event['evidence'];keys={'scheduler_terminal','known_pidfds_exited','reap_evidence_complete','same_domain_identity','subtree_empty_confirmed'}
            check(set(proof)==keys and all(type(proof[k]) is bool for k in keys),'Invalid recovery evidence assertion')
            state='retired' if all(proof.values()) else 'recovery_unverified'
        elif kind=='recovery_deadline':
            wait=job_ns if state=='waiting_job' else step_ns
            check(state in ('waiting_step','waiting_job') and now-request_time>=wait,'Recovery deadline out of order')
            state='recovery_unverified'
        elif kind=='recovery_observation_unidentified':
            check(state=='waiting_step' and event.get('reason')=='step_terminal_accounting_unidentified',
                  'Unidentified recovery observation out of order')
            state='recovery_unverified'
        elif kind=='worker_finished':
            if normal:check(len(checkpoints)==8,'Eight normal checkpoints required before stop completion')
            check(state=='idle' and active is None,'Worker finished with active/failed case');state='retired'
        else:raise ValueError('Unknown supervision event')
    return {'schema':'supervision-v3-replay','evidence':'offline_model_assertions_not_live_acceptance',
            'model_state':state,'model_active_case':active,'model_cases_seen':len(seen),'normal_checkpoints':checkpoints,'outcomes':outcomes,
            'cancellation_intents':actions,'mutating_commands_executed':0,'probe_calls':0,
            'scientific_profile':False,**dict.fromkeys(GATES,False)}

def run(*args,**kwargs):
    raise PermissionError('v3 live transport/native acceptance payload are not released; no job, signal or probe started')

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action',required=True)
    s.add_parser('plan');q=s.add_parser('prepare');q.add_argument('--inventory',required=True);q.add_argument('--output',required=True);q.add_argument('--scenario',choices=SCENARIOS,required=True)
    q=s.add_parser('replay');q.add_argument('--root',required=True);q.add_argument('--lease',required=True);q.add_argument('--events',required=True);q.add_argument('--output')
    q=s.add_parser('run');q.add_argument('--root',required=True);q.add_argument('--execute',action='store_true');q.add_argument('--owner-approved',action='store_true')
    args=vars(p.parse_args());action=args.pop('action')
    if action=='plan':value=plan()
    elif action=='prepare':value=prepare(**args)
    elif action=='run':value=run(**args)
    else:
        output=args.pop('output');value=replay(load_draft(args['root']),readonly.read(args['lease']),readonly.read(args['events']))
        if output:write(absolute(output,False),value)
    print(json.dumps(value,indent=2,allow_nan=False))

if __name__=='__main__':main()
