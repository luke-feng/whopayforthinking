"""Two-commit source registration; source identity is NOT an execution grant."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import contextvars
import os
import stat
import time
import weakref
from copy import deepcopy
from contextlib import contextmanager

ROOT=Path(__file__).resolve().parents[2]
REGISTRATION='experiments/calibration/supervision-v3-source-registration.json'
FILES=('scripts/calibration/lcb_supervision_release_v3.py',
       'scripts/calibration/lcb_supervision_wire_v3.py',
       'scripts/calibration/lcb_supervision_cancel_v3.py',
       'scripts/calibration/lcb_supervision_runtime_v3.py',
       'scripts/calibration/lcb_supervision_control_v3.py',
       'scripts/calibration/lcb_supervision_site_v3.py',
       'scripts/calibration/lcb_supervisor_v3.py',
       'scripts/calibration/lcb_slurm_readonly_v3.py',
       'scripts/calibration/native/supervision_fixture.c',
       'scripts/calibration/native/rootless_permission_abi.h',
       'experiments/calibration/supervision-v3-acceptance.json',
       'experiments/calibration/execution-boundary-supervision-v3.decision.json',
       'experiments/calibration/supervision-v3-wire-contract.json')
GATES=('owner_execution_approved','trusted_probe_authorized','candidate_execution_authorized','main_matrix_authorized')
FILES_V4=FILES+('scripts/calibration/lcb_supervision_owner_v3.py',
               'scripts/calibration/lcb_supervision_acceptance_v3.py',
               'experiments/calibration/supervision-normal-worker.slurm',
               'experiments/calibration/supervision-normal-observer.slurm')
FILES_V5=FILES_V4+('scripts/calibration/lcb_metering_clock.py',
                 'scripts/calibration/lcb_live_metering.py',
                 'scripts/calibration/lcb_metering_export.py',
                 'scripts/calibration/lcb_metering_cpu_return.py',
                 'scripts/calibration/lcb_worker_metering_v1.py',
                 'scripts/calibration/lcb_worker_metering_v2.py',
                 'experiments/calibration/worker-metering-v2.contract.json',
                 'experiments/calibration/live-metering-v1.contract.json')
BINDINGS='experiments/calibration/scheduler-normal-runtime-bindings-v1.json'
BASE='/home/researcher/www27-scheduler-normal-v3'
SOURCE=BASE+'/source'
ATTEMPT_PATTERN=BASE+'/www27-supervision-v3.attempt-[0-9]{3}'
CONFIG_PATTERN=ATTEMPT_PATTERN+'/role-config.json'
CONFIG_RE=re.compile(re.escape(BASE)+r'/www27-supervision-v3\.attempt-[0-9]{3}/role-config\.json')
# Wiring registers ONLY the fixed filename 'reviewed-release.json'.
# Its independently supplied digest must NOT be compiled into code A (the
# record binds B, whose hashes include this code). No hash self-reference.
RELEASE_REVIEW='reviewed-release.json'
_AUTHORITIES=weakref.WeakKeyDictionary()
_PERMITS=weakref.WeakKeyDictionary()
NORMAL_CASES=tuple('normal-%02d'%i for i in range(1,9))
OPERATIONS=('submit_observer','submit_worker','create_worker_ipc','exec_registered_fixture','attach_observer',
            'dispatch_normal_case','checkpoint_normal_case','stop_registered_fixture','observe_registered_set','record_own_accounting')
CONSTRAINTS={'partition':'standard','cluster':'cluster','worker_walltime_s':1200,'observer_walltime_s':2700,
             'observer_wait_s':600,'observer_min_remaining_s':1740,'setup_window_s':120,'cpus_per_job':1,
             'memory_bytes_per_job':1073741824,'gpus_per_job':0,'nodes_per_job':1,'requeue':False,
             'batch_flag':1,'restarts':0,'same_node':True}
NODE_POLICY={'source':'owner_approval','min_items':1,'max_items':16,
             'pattern':r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}','selection':'first_eligible_in_owner_order',
             'deadline_enabled':True}
_BUDGET=contextvars.ContextVar('supervision_setup_budget',default=None)
_ISSUER=object()


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()


class SetupBudget:
    """Seven measured stages sharing W's non-extending monotonic anchor.

    Limits are observation/dispatch bounds, not a guarantee to kill blocked I/O.
    The logger is supplied by the already-approved private owner launcher.
    """
    LIMITS=(20,25,25,10,25,10,5)
    def __init__(self,anchor_ns,record,clock=time.monotonic_ns):
        check(type(anchor_ns) is int and 0<anchor_ns<=clock(),'Invalid setup anchor')
        self.anchor=anchor_ns;self.record=record;self.clock=clock;self.end=None;self.used=set();self.elapsed={};self.last_stage=0
    def timeout(self,maximum):
        check(self.end is not None,'No active bounded setup stage')
        remaining=(self.end-self.clock())/1e9
        check(remaining>0,'Setup stage deadline expired')
        return min(maximum,remaining)
    @contextmanager
    def stage(self,number):
        check(type(number) is int and 1<=number<=7 and number>=self.last_stage and self.end is None,'Backwards/nested/invalid setup stage')
        began=self.clock();self.used.add(number)
        self.last_stage=number;charged=self.elapsed.get(number,0)
        check(began>=self.anchor,'Setup clock regressed')
        self.end=min(self.anchor+sum(self.LIMITS[:number])*10**9,began+self.LIMITS[number-1]*10**9-charged)
        token=_BUDGET.set(self);ok=False
        try:
            self.timeout(1);yield self;self.timeout(1);ok=True
        finally:
            end=self.clock();self.elapsed[number]=charged+end-began
            self.record('setup_stage',{'stage':number,'begin_ns':began,'end_ns':end,
                'elapsed_ns':end-began,'stage_limit_s':self.LIMITS[number-1],
                'aggregate_elapsed_ns':self.elapsed[number],'shared_deadline_ns':self.anchor+120*10**9,'stage_deadline_ns':self.end,'passed':ok})
            _BUDGET.reset(token);self.end=None


def timeout(maximum):
    budget=_BUDGET.get()
    return budget.timeout(maximum) if budget is not None else maximum


def check(ok,msg):
    if not ok:raise ValueError(msg)


def nodes_check(value):
    check(type(value) is list and 1<=len(value)<=NODE_POLICY['max_items'] and
          all(type(n) is str and re.fullmatch(NODE_POLICY['pattern'],n) for n in value) and
          len(set(value))==len(value),'One to sixteen distinct literal owner-approved nodes required')
    return tuple(value)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        out={}
        for k,v in items:check(k not in out,'Duplicate registration key');out[k]=v
        return out
    def bad(_):raise ValueError('Nonfinite registration')
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)
    json.dumps(value,allow_nan=False);return value


def git(*args):
    return subprocess.run(['git','-c','core.hooksPath=/dev/null','-C',str(ROOT),*args],
                          check=True,capture_output=True,timeout=timeout(1 if _BUDGET.get() else 30),
                          env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}).stdout


def config_path_check(path):
    """Check a literal path without filesystem access or caller-supplied regex."""
    check(isinstance(path,(str,Path)) and CONFIG_RE.fullmatch(str(path)) is not None,
          'Config must be under the fixed v3 base and exact attempt-NNN directory')
    return str(path)


def bind_for_config(binding,config_path):
    """Pure expansion of an authenticated template; never creates authority.

    Only four kinds of values change: draft_root, config_path, and the last
    config argument of each of the two profiles. Hash checks remain upstream.
    """
    path=config_path_check(config_path)
    check(binding['schema']=='scheduler-normal-runtime-bindings-v2' and
          binding['source_checkout']==SOURCE and binding['draft_root']==ATTEMPT_PATTERN and
          binding['config_path']==CONFIG_PATTERN and set(binding['profiles'])=={'worker','observer'},
          'Not the fixed path-template binding')
    out=deepcopy(binding);out['draft_root']=str(Path(path).parent);out['config_path']=path
    for role,profile in out['profiles'].items():
        expected=[binding['python_path'],'-I','-B',SOURCE+'/scripts/calibration/lcb_supervision_runtime_v3.py',
                  role,'--config',CONFIG_PATTERN]
        check(profile['argv']==expected,'Unexpected profile template')
        profile['argv'][-1]=path
    return out


def bindings_check(value,hashes):
    check(set(value)=={'schema','status','scenario','owner_uid','source_checkout','draft_root','config_path',
        'runtime','python_path','python_sha256','scontrol_path','profiles','case_ids','constraints','release_review',
        'partition_confirmation','execution_enabled','approved_nodes',*GATES},'Unexpected runtime binding keys/self reference')
    check(value['schema']=='scheduler-normal-runtime-bindings-v2' and value['status']=='registered_pending_implementation_review'
          and value['scenario']=='scheduler-normal' and value['execution_enabled'] is False and
          all(value[g] is False for g in GATES),'Bindings are not execution authority')
    check(value['owner_uid']==891991027 and type(value['owner_uid']) is int and
          value['source_checkout']==SOURCE and value['draft_root']==ATTEMPT_PATTERN and
          value['config_path']==CONFIG_PATTERN,'Fixed runtime path templates/owner differ')
    check(encoded(value['approved_nodes'])==encoded(NODE_POLICY),'Node policy differs')
    runtime=value['runtime'];check(set(runtime)=={'native_path','native_sha256','scontrol_sha256','cancellation_transport'}
          and runtime['cancellation_transport']=='closed','Only closed four-key runtime is supported')
    check(value['case_ids']==list(NORMAL_CASES) and encoded(value['constraints'])==encoded(CONSTRAINTS),'Case/resource policy differs')
    check(value['python_path']=='/usr/bin/python3.12' and value['scontrol_path']=='/usr/bin/scontrol','Pinned clients required')
    for digest in (value['python_sha256'],runtime['native_sha256'],runtime['scontrol_sha256']):
        check(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'Missing runtime digest')
    check(set(value['profiles'])=={'worker','observer'},'Two fixed profiles required')
    expected={value['source_checkout']+'/'+p:h for p,h in hashes.items() if p.endswith('.py')}
    for role,profile in value['profiles'].items():
        check(set(profile)=={'executable_sha256','argv','source_files'} and profile['executable_sha256']==value['python_sha256']
              and profile['source_files']==expected and profile['argv']==[value['python_path'],'-I','-B',
              value['source_checkout']+'/scripts/calibration/lcb_supervision_runtime_v3.py',role,'--config',value['config_path']],
              'Runtime profile does not bind the exact source set/argv')
    # An acceptance refers to bindings, never the inverse: no digest cycles.
    check(value['release_review'] is None and value['partition_confirmation'] is None,
          'Pending bindings cannot self-authorize a review/partition')
    return value


def source_snapshot(*,require_clean=True):
    """Audit mode may tolerate unrelated dirt but never tracked-code drift."""
    path=ROOT/REGISTRATION
    check(path.is_file() and not path.is_symlink() and path.stat().st_size<=65536,'Regular bounded registration required')
    raw=path.read_bytes();v=strict(raw)
    check(set(v)=={'schema','status','source_sha','files_sha256','runtime_bindings',*GATES} and
          (v['schema'],v['status']) in (('supervision-source-registration-v3','source_registered_execution_closed'),
          ('supervision-source-registration-v4','source_and_runtime_registered_execution_closed'),
          ('supervision-source-registration-v5','source_and_runtime_registered_execution_closed')),
          'Source registration incomplete')
    v5=v['schema']=='supervision-source-registration-v5'
    v4=v['schema'] in ('supervision-source-registration-v4','supervision-source-registration-v5')
    check(all(v[k] is False for k in GATES),'Source registration cannot grant live access')
    if not v4:check(v['runtime_bindings'] is None,'Historical v3 bindings must be null')
    source=v['source_sha'];check(isinstance(source,str) and re.fullmatch('[0-9a-f]{40}',source),'Fixed source SHA required')
    head=git('rev-parse','HEAD').decode().strip();check(source!=head,'Registration must follow code commit')
    git('merge-base','--is-ancestor',source,head)
    status=git('status','--porcelain','--untracked-files=all','--ignored').decode()
    if require_clean:check(not status,'Clean runtime checkout required')
    check(git('show',head+':'+REGISTRATION)==raw,'Registration differs from selected HEAD')
    roster=FILES_V5 if v5 else FILES_V4 if v4 else FILES
    check(set(v['files_sha256'])==set(roster),'Source file roster differs')
    for name in roster:
        p=ROOT/name
        check(p.is_file() and not any(x.is_symlink() for x in (p,*p.parents)),'Regular canonical source required')
        body=p.read_bytes()
        check(git('show',source+':'+name)==git('show',head+':'+name)==body and sha(body)==v['files_sha256'][name],
              'Source bytes drifted: '+name)
    bindings=None
    if v4:
        ref=v['runtime_bindings']
        check(type(ref) is dict and set(ref)=={'path','sha256'} and ref['path']==BINDINGS,'Fixed bindings reference required')
        p=ROOT/BINDINGS;check(p.is_file() and p.stat().st_size<=65536,'Bounded runtime bindings required');body=p.read_bytes()
        check(not any(q.is_symlink() for q in (p,*p.parents)) and len(body)<=65536 and sha(body)==ref['sha256'] and
              git('show',source+':'+BINDINGS)==git('show',head+':'+BINDINGS)==body,'Bindings bytes/lineage differ')
        bindings=bindings_check(strict(body),v['files_sha256'])
        contract=strict((ROOT/'experiments/calibration/supervision-v3-wire-contract.json').read_bytes())
        check(type(contract) is dict and contract.get('peer_runtime_profiles')==bindings['profiles'] and
              contract.get('native_binary_digest')==bindings['runtime']['native_sha256'] and
              contract.get('cancellation_client_digest') is None and
              contract.get('cancellation_client_digest_reason')=='scheduler_normal_transport_closed' and
              all(contract.get(k) is False for k in ('execution_enabled','trusted_probe_authorized','candidate_execution_authorized','main_matrix_authorized')),
              'Wire contract/bindings/closed scope differ')
    return {'schema':'supervision-source-snapshot-v5' if v5 else 'supervision-source-snapshot-v4' if v4 else 'supervision-source-snapshot-v3','source_sha':source,'tools_head':head,
            'registration_sha256':sha(raw),'files_sha256':v['files_sha256'],
            **({'runtime_bindings':bindings,'runtime_bindings_sha256':v['runtime_bindings']['sha256']} if v4 else {}),
            'clean_checkout':not status,'execution_enabled':False,**dict.fromkeys(GATES,False)}


def owner_path(path,uid,*,private=False):
    """Check every ancestor; no permissive fallback for a writable parent."""
    p=Path(path);check(p.is_absolute() and str(p)==str(p.resolve(strict=True)) and '..' not in p.parts,'Canonical existing path required')
    for q in reversed((p,*p.parents)):
        st=q.lstat();check(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,uid) and not st.st_mode&0o022,
                          'Unsafe parent owner/mode/symlink: '+str(q))
    st=p.stat()
    mode_ok=(stat.S_ISDIR(st.st_mode) and st.st_mode&0o777==0o700 or
             stat.S_ISREG(st.st_mode) and st.st_mode&0o777==0o600)
    check(st.st_uid==uid and (not private or mode_ok),'Owner/private mode mismatch')
    return p


def pinned_binary(path,expected,uid):
    """Read-only file and complete parent-chain validation; never execute."""
    p=Path(path);check(p.is_absolute() and str(p)==str(p.resolve(strict=True)) and '..' not in p.parts,'Canonical binary required')
    for q in (p,*p.parents):
        st=q.lstat();check(st.st_uid in (0,uid) and not st.st_mode&0o022 and not stat.S_ISLNK(st.st_mode),
                          'Unsafe binary/parent owner or mode')
    a=p.stat();check(stat.S_ISREG(a.st_mode) and not a.st_mode&0o6000 and a.st_mode&0o111 and 0<a.st_size<=64*1024**2,
                     'Unsafe binary format/mode/size')
    raw=p.read_bytes();b=p.stat()
    check((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
          and sha(raw)==expected,'Pinned binary changed')
    return {'path':str(p),'sha256':expected,'device':a.st_dev,'inode':a.st_ino,'mode':stat.S_IMODE(a.st_mode)}


def approval_check(raw,expected_sha,*,draft,draft_raw,config_raw,snapshot,bindings_raw,review_sha,now_ns):
    """Pure validation; never issues authority or writes an approval."""
    check(type(raw) is bytes and len(raw)<=65536 and sha(raw)==expected_sha,'Independent approval digest mismatch')
    v=strict(raw);check(encoded(v)==raw,'Noncanonical approval encoding')
    keys={'schema','owner_approved','owner_uid','scenario','attempt_nonce','draft_root','source_checkout','draft_sha256',
          'config_sha256','source_registration_sha256','bindings_sha256','release_review_sha256','issued_wall_ns',
          'expires_wall_ns','case_ids','allowed_operations','job_constraints','approved_nodes'}
    check(set(v)==keys and v['schema']=='scheduler-normal-owner-approval-v2' and v['owner_approved'] is True,
          'Exact owner approval required')
    cfg=strict(config_raw)
    check(type(cfg) is dict and type(cfg.get('draft_root')) is str,'Config draft_root must be a literal path')
    binding=bind_for_config(snapshot['runtime_bindings'],cfg['draft_root']+'/role-config.json')
    draft_keys={'schema','purpose','source','scenario','attempt_nonce','expected_job_name','expected_job_comment','owner_uid',
                'inventory_sha256','screening','plan_sha256','fixed_plan','runtime_bindings','live_transport_bound','owner_approved',
                'implementation_approved','trusted_probe_authorized','candidate_execution_authorized','main_matrix_authorized','site_recovery_verified'}
    check(set(draft)==draft_keys,'Draft graph must not contain descendant/config/approval references')
    check(set(cfg)=={'schema','draft_root','case_ids','runtime','profiles'} and cfg['runtime']==binding['runtime'] and
          cfg['profiles']==binding['profiles'] and cfg['schema']=='supervision-role-config-v3','Config graph/schema differs')
    check(type(v['owner_uid']) is int and v['owner_uid']==draft['owner_uid']==binding['owner_uid'] and
          v['scenario']==draft['scenario']=='scheduler-normal' and v['attempt_nonce']==draft['attempt_nonce'],
          'Owner/scenario/nonce differs')
    check(v['draft_root']==cfg['draft_root']==binding['draft_root'] and v['source_checkout']==binding['source_checkout']
          and v['case_ids']==binding['case_ids']==cfg['case_ids']==list(NORMAL_CASES),'Draft/config/cases differ')
    check(strict(draft_raw)==draft and v['draft_sha256']==sha(draft_raw) and v['config_sha256']==sha(config_raw) and
          v['source_registration_sha256']==snapshot['registration_sha256'] and
          v['bindings_sha256']==sha(bindings_raw)==snapshot['runtime_bindings_sha256'] and
          v['release_review_sha256']==review_sha,'Approval digest graph mismatch')
    check(v['allowed_operations']==list(OPERATIONS) and encoded(v['job_constraints'])==encoded(CONSTRAINTS),'Operation/resource scope differs')
    check(encoded(snapshot['runtime_bindings']['approved_nodes'])==encoded(NODE_POLICY),'Unbound node policy')
    nodes_check(v['approved_nodes'])
    a,b=v['issued_wall_ns'],v['expires_wall_ns']
    check(type(a) is int and type(b) is int and a<=now_ns<b and 0<b-a<=3600*10**9,'Approval future/expired/too long')
    return v


def consume_approval(root,approval,approval_sha):
    """One launch only; partial/crashed claims remain consumed, never retried."""
    path=owner_path(root,approval['owner_uid'],private=True)/'approval-consumed.json'
    body=encoded({'schema':'scheduler-normal-approval-consumption-v1','approval_sha256':approval_sha,
                  'nonce':approval['attempt_nonce'],'config_sha256':approval['config_sha256']})
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(body)
        while view:
            n=os.write(fd,view);check(n>0,'Consumption write failed');view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    return strict(body)


class _Permit:
    def __init__(self,key,authority,phase,role,session=None):
        check(key is _ISSUER,'Only the trusted issuer constructs a permit')
        self.authority=authority;self.phase=phase;self.role=role;self.session=session
        self.lease_sha=sha(encoded(session.lease)) if session is not None else None
        self.pid=os.getpid();self.birth=time.monotonic_ns();self.used=set()


class Authority:
    """Per-attempt phase issuer. No public execution bypass; same-UID trust only."""
    PHASES={'launch':('owner',{'submit_observer','submit_worker'}),
            'worker_bootstrap':('worker',{'create_worker_ipc'}),
            'observer_bootstrap':('observer',{'attach_observer'}),
            'native_bootstrap':('native',{'exec_registered_fixture'}),
            'worker_attach':('worker',{'attach_observer'}),
            'observer_attach':('observer',{'attach_observer','observe_registered_set','checkpoint_normal_case'}),
            'normal_dispatch':('worker',{'dispatch_normal_case','checkpoint_normal_case','stop_registered_fixture'})}
    def __init__(self,key,approval,snapshot,approval_sha,launch_only=False):
        check(key is _ISSUER,'Verified approval/release required')
        self.approval=approval;self.snapshot=snapshot;self.approval_sha=approval_sha;self.started=[];self.completed=[]
        self.launch_only=launch_only
    def mint(self,phase,session=None):
        require_live(self)
        check(phase in self.PHASES,'Unknown permit phase')
        check(not self.launch_only or phase=='launch','Unconsumed launch approval cannot issue role permits')
        if phase in ('normal_dispatch','observer_attach','worker_attach'):
            check(session is not None and session.draft['attempt_nonce']==self.approval['attempt_nonce'] and
                  session.lease['uid']==self.approval['owner_uid'],'A live matching E lease is required')
            obs=session.observe();check(obs['job']['state']=='RUNNING','Cannot mint against a retired job')
            check(session.context['uid']==os.getuid() and session.context['node']==session.lease['node'],'Live role context differs')
        permit=_Permit(_ISSUER,self,phase,self.PHASES[phase][0],session)
        _PERMITS[permit]=(self,phase,permit.role,session,permit.lease_sha,permit.pid)
        return permit


def operation(permit,name,*,role=None,session=None,case_id=None,consume=False):
    require_live(permit)
    check(type(permit) is _Permit and permit.pid==os.getpid(),'Unissued/inherited permit')
    a=permit.authority;check(a.approval.get('issued_wall_ns',0)<=time.time_ns()<a.approval['expires_wall_ns'] and name in Authority.PHASES[permit.phase][1]
          and (role is None or role==permit.role),'Expired/wrong operation or role')
    check(a.approval['scenario']=='scheduler-normal','Wrong scenario')
    if session is not None:
        check(permit.session is session and permit.lease_sha==sha(encoded(session.lease)),'Wrong live lease')
    if name in ('dispatch_normal_case','checkpoint_normal_case'):
        check(case_id in NORMAL_CASES,'Unapproved case')
        if name=='dispatch_normal_case':
            check(0<=time.monotonic_ns()-session.last_observation['observed_ns']<=5*10**9 and
                  a.started==a.completed and len(a.started)<8 and case_id==NORMAL_CASES[len(a.started)],'Stale/replayed/unclosed dispatch')
            if consume:a.started.append(case_id)
        elif permit.role=='worker':
            check(len(a.started)==len(a.completed)+1 and a.started[-1]==case_id,'No pending case checkpoint')
            if consume:a.completed.append(case_id)
    if name=='stop_registered_fixture':check(a.completed==list(NORMAL_CASES),'Stop requires eight checkpoints')
    if consume and name not in ('dispatch_normal_case','checkpoint_normal_case'):
        check(name not in permit.used,'Operation already consumed');permit.used.add(name)


def preflight_request(config_path,approval_sha,review_sha256=None):
    """Pure entry scope check, NOT authority to create files or run anything.

    The fixed role can read its own config/anchor before opening its charged
    setup stage. Authority is issued only after all checks in issuer_from_paths.
    """
    expected=review_sha256 if review_sha256 is not None else os.environ.get('WWW27_RELEASE_REVIEW_SHA256')
    if (str(ROOT)!=SOURCE or CONFIG_RE.fullmatch(str(config_path)) is None or os.getuid()!=891991027 or
        not isinstance(approval_sha,str) or re.fullmatch('[0-9a-f]{64}',approval_sha) is None or
        not isinstance(expected,str) or re.fullmatch('[0-9a-f]{64}',expected) is None):
        raise PermissionError('Fixed scheduler-normal request and independent owner/review digests required')
    return expected


def issuer_from_paths(approval_path,approval_sha,config_path,*,for_submission=False,review_sha256=None):
    expected_review=preflight_request(config_path,approval_sha,review_sha256)
    check(type(for_submission) is bool,'Explicit submission mode required')
    check(str(approval_path)==str(Path(config_path).parent/'owner-approval.json'),'Fixed owner approval path required')
    check(RELEASE_REVIEW is not None,'Implementation/wrapper acceptance is not registered')
    # A future registration must bind reviewer bytes, partition confirmation,
    # source registration and bindings independently; no self-reported hashes.
    check(RELEASE_REVIEW=='reviewed-release.json','Fixed external release filename required')
    check(isinstance(expected_review,str) and re.fullmatch('[0-9a-f]{64}',expected_review),'Independent reviewer digest required')
    snapshot=source_snapshot();bindings_raw=(ROOT/BINDINGS).read_bytes();binding=snapshot['runtime_bindings']
    check(sha(bindings_raw)==snapshot['runtime_bindings_sha256'] and strict(bindings_raw)==binding,
          'Runtime binding bytes changed after source verification')
    uid=os.getuid();root=Path(config_path_check(config_path)).parent;owner_path(root,uid,private=True)
    review_path=owner_path(root/RELEASE_REVIEW,uid,private=True)
    check(review_path.stat().st_size<=65536,'Bounded release record required')
    raw=review_path.read_bytes();check(len(raw)<=65536 and sha(raw)==expected_review,'Release review drift')
    review=strict(raw)
    check(encoded(review)==raw,'Noncanonical release record')
    check(set(review)=={'schema','implementation_review','wrapper_review','source_registration_sha256','bindings_sha256','partition_confirmation'},
          'Exact independent release record required')
    check(review['schema']=='scheduler-normal-reviewed-release-v1' and review['source_registration_sha256']==snapshot['registration_sha256']
          and review['bindings_sha256']==sha(bindings_raw),'Release digest graph differs')
    names={'implementation_review':'implementation-review.md','wrapper_review':'wrapper-review.md','partition_confirmation':'partition-confirmation.json'}
    for key,name in names.items():
        r=review[key];check(set(r)=={'path','sha256'} and r['path']==name,'Fixed private review/site record required')
        p=owner_path(root/name,uid,private=True);check(sha(p.read_bytes())==r['sha256'],'Missing accepted review/site record')
    partition=strict((root/review['partition_confirmation']['path']).read_bytes())
    check(partition=={'partition':'standard','owner_confirmed':True},'CPU partition not owner-confirmed')
    resolved=bind_for_config(binding,config_path)
    owner_path(approval_path,uid,private=True);owner_path(config_path,uid,private=True)
    check(Path(approval_path).stat().st_size<=65536 and Path(config_path).stat().st_size<=65536,'Bounded owner/config records required')
    config_raw=Path(config_path).read_bytes();cfg=strict(config_raw)
    for name in ('draft.json','draft.sha256.json','slurm-inventory.json'):owner_path(root/name,uid,private=True)
    import lcb_supervisor_v3 as core
    draft=core.load_draft(cfg['draft_root'])
    v=approval_check(Path(approval_path).read_bytes(),approval_sha,draft=draft,draft_raw=(Path(cfg['draft_root'])/'draft.json').read_bytes(),config_raw=config_raw,
                     snapshot=snapshot,bindings_raw=bindings_raw,review_sha=expected_review,now_ns=time.time_ns())
    check(uid==v['owner_uid'] and str(ROOT)==binding['source_checkout'] and str(config_path)==resolved['config_path'] and
          cfg['draft_root']==resolved['draft_root'],
          'Actual UID/source/config differs')
    owner_path(ROOT,uid)
    for name in snapshot['files_sha256']:owner_path(ROOT/name,uid)
    for path,digest in ((binding['python_path'],binding['python_sha256']),
                        (binding['scontrol_path'],binding['runtime']['scontrol_sha256']),
                        (binding['runtime']['native_path'],binding['runtime']['native_sha256'])):
        pinned_binary(path,digest,uid)
    if not for_submission:
        claim=Path(v['draft_root'])/'approval-consumed.json';owner_path(claim,uid,private=True)
        check(strict(claim.read_bytes())=={'schema':'scheduler-normal-approval-consumption-v1','approval_sha256':approval_sha,
              'nonce':v['attempt_nonce'],'config_sha256':v['config_sha256']},'Owner launch is unconsumed/foreign')
    authority=Authority(_ISSUER,v,snapshot,approval_sha,launch_only=for_submission)
    _AUTHORITIES[authority]=(os.getpid(),uid,approval_sha,sha(encoded(snapshot)),expected_review,for_submission)
    return authority


def require_live(permit=None,*,operation=None):
    """Only same-process issued authority/permits; no dict, None or flag gate.

    A source registration stays non-authorizing. The issuer must first verify
    clean source, independent R, its originals, owner approval and consumption.
    """
    if type(permit) is Authority:
        authority=permit
        if operation is not None:raise PermissionError('Authority must mint a phase permit before an operation')
    elif type(permit) is _Permit:
        proof=_PERMITS.get(permit)
        if proof is None or proof!=(permit.authority,permit.phase,permit.role,permit.session,permit.lease_sha,permit.pid):
            raise PermissionError('Unissued or modified phase permit')
        authority=permit.authority
        if permit.pid!=os.getpid() or permit.phase not in Authority.PHASES or permit.role!=Authority.PHASES[permit.phase][0]:
            raise PermissionError('Inherited or invalid phase permit')
        if permit.session is not None and permit.lease_sha!=sha(encoded(permit.session.lease)):
            raise PermissionError('Phase lease changed')
        if operation is not None and operation not in Authority.PHASES[permit.phase][1]:
            raise PermissionError('Operation outside scheduler-normal permit')
    else:
        raise PermissionError('Issued scheduler-normal authority or phase permit required')
    proof=_AUTHORITIES.get(authority)
    if proof is None:raise PermissionError('Authority did not pass the live issuer')
    pid,uid,approval_sha,snapshot_sha,review_sha,launch_only=proof
    v=authority.approval;s=authority.snapshot
    if (pid!=os.getpid() or uid!=os.getuid() or authority.approval_sha!=approval_sha or
        sha(encoded(v))!=approval_sha or sha(encoded(s))!=snapshot_sha or
        authority.launch_only is not launch_only or v['release_review_sha256']!=review_sha or
        v['scenario']!='scheduler-normal' or v['owner_uid']!=uid or
        not v['issued_wall_ns']<=time.time_ns()<v['expires_wall_ns'] or
        s.get('clean_checkout') is not True or s.get('execution_enabled') is not False or
        any(s.get(g) is not False for g in GATES)):
        raise PermissionError('Authority identity, owner, expiry or verified source changed')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['inspect-source']);p.add_argument('--allow-unrelated-dirty',action='store_true')
    a=p.parse_args();print(json.dumps(source_snapshot(require_clean=not a.allow_unrelated_dirty),indent=2))


if __name__=='__main__':main()
