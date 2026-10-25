"""Narrow Slurm metadata reader; no submission, cancellation or probe commands.

Only explicit owner-approved collection invokes scontrol --version/show config.
Raw configuration is minimized to selected lines; hashes do not attest runtime behavior.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
DECISION='experiments/calibration/execution-boundary-supervision-v3.decision.json'
DECISION_SHA='48cdc756e18aa64729ba99b2da87fd6494eb9e5f8bb3611647c3839f3bb810d9'
COMMANDS=(('--version',),('show','config'))
LEGACY_READER_SHA='cad8cb34f1cb12e9c1430c797cff97de6bfa73d74d6c9bd41b58b83f8e0463ba'
LEGACY_KEYS=('ClusterName','SLURM_VERSION','ProctrackType','TaskPlugin','JobAcctGatherType',
      'KillWait','MessageTimeout','SlurmdTimeout','UnkillableStepTimeout','UnkillableStepProgram',
      'WaitTime','PrologEpilogTimeout')
KEYS=LEGACY_KEYS+('PrologTimeout','EpilogTimeout')
TIMER_KEYS=('KillWait','MessageTimeout','SlurmdTimeout','UnkillableStepTimeout','WaitTime',
            'PrologEpilogTimeout','PrologTimeout','EpilogTimeout')
SCRIPT_TIMERS=('PrologEpilogTimeout','PrologTimeout','EpilogTimeout')
SCHEMA='slurm-tracking-readonly-v3.1'
GATES=('implementation_approved','trusted_probe_authorized','candidate_execution_authorized',
       'main_matrix_authorized','site_recovery_verified','site_resource_enforcement_verified')
MAX_OUTPUT=262144

def check(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:check(k not in value,'Duplicate JSON key');value[k]=v
        return value
    def bad(_):raise ValueError('Nonfinite JSON value')
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=bad);json.dumps(value,allow_nan=False)
    return value

def read(path):
    p=Path(path);check(p.is_file() and not p.is_symlink() and p.stat().st_size<=1048576,'Bounded regular JSON required')
    return strict(p.read_bytes())

def file_identity(path):
    p=Path(path).resolve(strict=True);before=p.stat()
    check(p.is_file() and before.st_size<=256*1024**2,'Bounded regular client required')
    h=hashlib.sha256()
    with p.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
    after=p.stat()
    keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
    check(all(getattr(before,k)==getattr(after,k) for k in keys),'Client changed while hashing')
    return {'path':str(p),'sha256':h.hexdigest(),'bytes':before.st_size,'device':before.st_dev,
            'inode':before.st_ino,'mtime_ns':before.st_mtime_ns,'ctime_ns':before.st_ctime_ns}

def source_identity():
    decision=(ROOT/DECISION).read_bytes();check(sha(decision)==DECISION_SHA,'Wrong v3 decision bytes')
    return {'reader_sha256':sha(Path(__file__).read_bytes()),'decision_sha256':sha(decision)}

def bounded_command(binary,args):
    check(tuple(args) in COMMANDS,'Only read-only scontrol metadata commands are allowed')
    check(Path(binary).is_absolute(),'Resolved absolute client path required')
    env=os.environ.copy();env.update(LC_ALL='C',TZ='UTC')
    began=time.monotonic_ns();buf={k:bytearray() for k in ('stdout','stderr')};reason=None;rc=None;proc=None
    selector=selectors.DefaultSelector();reaped=True
    try:
        proc=subprocess.Popen([str(binary),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,env=env,close_fds=True)
        reaped=False
        for stream,key in ((proc.stdout,'stdout'),(proc.stderr,'stderr')):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,key)
        while selector.get_map():
            if time.monotonic_ns()-began>=10_000_000_000:reason='timeout';break
            for key,_ in selector.select(.05):
                chunk=os.read(key.fd,min(8192,MAX_OUTPUT-len(buf[key.data])+1))
                if not chunk:selector.unregister(key.fileobj);continue
                buf[key.data].extend(chunk)
                if len(buf[key.data])>MAX_OUTPUT:reason='output_limit';break
            if reason:break
        if not reason:
            remaining=max(.001,10-(time.monotonic_ns()-began)/1e9)
            try:rc=proc.wait(timeout=remaining);reaped=True
            except subprocess.TimeoutExpired:reason='timeout'
    except OSError as exc:reason=type(exc).__name__
    finally:
        selector.close()
        if proc is not None:
            if not reaped:
                if proc.poll() is None:
                    try:proc.kill()  # Only the metadata child just started here.
                    except ProcessLookupError:pass
                try:rc=proc.wait(timeout=1);reaped=True
                except subprocess.TimeoutExpired:reason='metadata_child_cleanup_unverified'
            for stream in (proc.stdout,proc.stderr):
                if stream is not None:stream.close()
    return {'args':list(args),'status':'ok' if reason is None and rc==0 else 'error',
            'returncode':rc,'error':reason,'child_reaped':reaped,'start_ns':began,
            'end_ns':time.monotonic_ns(),'stdout':bytes(buf['stdout']),'stderr':bytes(buf['stderr'])}

def project(result):
    check(tuple(result['args']) in COMMANDS,'Unapproved command record')
    out={k:result[k] for k in ('args','status','returncode','error','child_reaped','start_ns','end_ns')}
    raw=result['stdout'];err=result['stderr']
    out.update(stdout_sha256=sha(raw),stderr_sha256=sha(err),stdout_bytes=len(raw),stderr_bytes=len(err),
               full_stdout_retained=False,full_stderr_retained=False)
    lines=raw.decode('utf-8',errors='replace').splitlines()
    if tuple(result['args'])==('--version',):
        selected=[x for x in lines if re.fullmatch(r'slurm [0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?',x)]
    else:
        selected=[x for x in lines if (m:=re.match(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=',x)) and m[1] in KEYS]
    out['selected_lines']=selected;out['selected_sha256']=sha(('\n'.join(selected)+'\n').encode())
    return out

def _parse(commands,keys):
    check([x['args'] for x in commands]==[list(x) for x in COMMANDS],'Metadata command roster differs')
    for r in commands:
        check(set(r)=={'args','status','returncode','error','child_reaped','start_ns','end_ns','stdout_sha256',
                       'stderr_sha256','stdout_bytes','stderr_bytes','full_stdout_retained','full_stderr_retained',
                       'selected_lines','selected_sha256'},'Unexpected command record fields')
        check(r['status'] in ('ok','error') and type(r['child_reaped']) is bool,'Invalid command result')
        check(r['returncode'] is None or type(r['returncode']) is int,'Invalid exit code')
        check(all(type(r[k]) is int and 0<=r[k]<=MAX_OUTPUT+1 for k in ('stdout_bytes','stderr_bytes')) and
              all(isinstance(r[k],str) and re.fullmatch('[0-9a-f]{64}',r[k]) for k in ('stdout_sha256','stderr_sha256')),
              'Invalid bounded output provenance')
        check(type(r['start_ns']) is int and type(r['end_ns']) is int and 0<r['start_ns']<=r['end_ns'],'Invalid command time')
        check(isinstance(r['selected_lines'],list) and all(isinstance(x,str) for x in r['selected_lines']),'Invalid selected lines')
        check(r['selected_sha256']==sha(('\n'.join(r['selected_lines'])+'\n').encode()),'Selected lines changed')
        check(r['full_stdout_retained'] is False and r['full_stderr_retained'] is False,'Unexpected raw config disclosure')
        if r['status']=='ok':check(r['returncode']==0 and r['error'] is None and r['child_reaped'],'Inconsistent successful command')
    fields=dict.fromkeys(keys);conflicts=[]
    for line in commands[1]['selected_lines']:
        match=re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*',line)
        check(match and match[1] in keys,'Unexpected configuration key')
        k,val=match.groups()
        if fields[k] is not None:conflicts.append(k)
        fields[k]=val
    versions=commands[0]['selected_lines'];version=versions[0][6:] if len(versions)==1 and versions[0].startswith('slurm ') else None
    check(all(re.fullmatch(r'slurm [0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?',x) for x in versions),'Invalid version record')
    status='unidentified_configuration'
    if all(r['status']=='ok' for r in commands) and not conflicts and version:
        if fields['ProctrackType'] and fields['ProctrackType']!='proctrack/cgroup':status='tracking_incompatible_with_selected_v3_route'
        elif fields['ProctrackType']=='proctrack/cgroup' and 'task/cgroup' in (fields['TaskPlugin'] or '').split(',') and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',fields['ClusterName'] or ''):
            status='configuration_reported_compatible_pending_trusted_acceptance'
    return {'screening':status,'client_version':version,'selected_fields':fields,
            'duplicate_config_keys':sorted(set(conflicts)),
            'live_node_configuration_proved':False,'cancellation_capability_proved':False,
            'candidate_admission':False}

def _legacy_analyze(commands):
    """Reproduce v3 literally, including the known NO_VAL16 interpretation error."""
    out=_parse(commands,LEGACY_KEYS);fields=out['selected_fields'];timers={}
    for k in TIMER_KEYS[:6]:
        m=re.fullmatch(r'([0-9]+)(?: sec)?',fields[k] or '')
        timers[k]=int(m[1]) if m and k not in out['duplicate_config_keys'] else None
    return {**{k:out[k] for k in ('screening','client_version','selected_fields','duplicate_config_keys')},
            'observed_seconds':timers,
            **{k:out[k] for k in ('live_node_configuration_proved','cancellation_capability_proved','candidate_admission')}}

def _timer(key,raw,duplicate,version_reviewed,command_ok):
    state='missing';seconds=None;number=None
    if duplicate:state='duplicate'
    elif raw is not None:
        match=re.fullmatch(r'([0-9]{1,5})(?: sec)?',raw)
        if match is None:state='invalid'
        else:
            number=int(match[1])
            if number>65535:state='invalid'
            elif not command_ok:state='command_failed'
            elif not version_reviewed:state='version_unreviewed'
            elif key in SCRIPT_TIMERS and number==65534:state='default_unlimited'
            elif key not in SCRIPT_TIMERS and number>=65534:state='special_unreviewed'
            else:state='zero' if number==0 else 'finite';seconds=number
    # NO_VAL16 is key-specific. The reviewed script path converts all OTHER
    # uint16 values to milliseconds, including 65535; no global INFINITE rule.
    return {'raw':raw,'parsed_integer':number,'state':state,'seconds':seconds}

def analyze(commands):
    out=_parse(commands,KEYS);fields=out['selected_fields'];conflicts=out['duplicate_config_keys']
    version_ok=out['client_version']==fields['SLURM_VERSION']=='25.05.4' and 'SLURM_VERSION' not in conflicts
    if out['client_version']!=fields['SLURM_VERSION']:
        out['screening']='unidentified_configuration'
    ok=all(row['status']=='ok' for row in commands)
    timers={k:_timer(k,fields[k],k in conflicts,version_ok,ok) for k in TIMER_KEYS}
    combined=fields['PrologEpilogTimeout'] is not None
    split=any(fields[k] is not None for k in ('PrologTimeout','EpilogTimeout'))
    layout='conflicting_combined_and_split' if combined and split else 'combined' if combined else 'split' if split else 'missing'
    effective={}
    for key in ('PrologTimeout','EpilogTimeout'):
        source='PrologEpilogTimeout' if layout=='combined' else key
        effective[key]={'source_field':source,**timers[source]}
        if layout=='conflicting_combined_and_split':
            effective[key].update(state='conflicting_combined_and_split',seconds=None)
    out.update(interpretation_policy='slurm-timeout-semantics-v1',
               semantic_version_reviewed=version_ok,
               observed_seconds={k:r['seconds'] for k,r in timers.items()},
               timeout_values=timers,prolog_epilog_layout=layout,effective_script_timeouts=effective)
    return out

def collect(*,owner_readonly_approved=False):
    if not owner_readonly_approved:return {'status':'plan_only','commands':[list(x) for x in COMMANDS],**dict.fromkeys(GATES,False)}
    before=source_identity();binary=shutil.which('scontrol')
    check(binary is not None,'scontrol unavailable; do not install or substitute another client')
    client=file_identity(binary)
    results=[]
    for args in COMMANDS:
        if results and results[-1]['child_reaped'] is False:
            now=time.monotonic_ns()
            raw={'args':list(args),'status':'error','returncode':None,'error':'not_attempted_previous_child_unreaped',
                 'child_reaped':True,'start_ns':now,'end_ns':now,'stdout':b'','stderr':b''}
        else:raw=bounded_command(client['path'],args)
        results.append(project(raw))
    after=source_identity();client_after=file_identity(binary)
    check(before==after and client==client_after,'Reader/client changed during collection')
    value={'schema':SCHEMA,'purpose':'configuration_evidence_not_recovery_acceptance',
           'owner_readonly_approved':True,'source_before':before,'source_after':after,
           'client_before':client,'client_after':client_after,'observed_at_unix_ns':time.time_ns(),
           'host':{'node':os.uname().nodename,'uid':os.getuid()},'commands':results,
           'analysis':analyze(results),'probe_calls':0,'cancellation_calls':0,'submission_calls':0,
           **dict.fromkeys(GATES,False)}
    validate(value);return value

def validate(value):
    expected={'schema','purpose','owner_readonly_approved','source_before','source_after','client_before','client_after',
              'observed_at_unix_ns','host','commands','analysis','probe_calls','cancellation_calls','submission_calls',*GATES}
    check(set(value)==expected and value['schema'] in ('slurm-tracking-readonly-v3',SCHEMA) and
          value['purpose']=='configuration_evidence_not_recovery_acceptance' and value['owner_readonly_approved'] is True,'Wrong inventory schema/purpose')
    check(value['source_before']==value['source_after'] and value['source_before']['decision_sha256']==DECISION_SHA,'Wrong source identity')
    check(set(value['source_before'])=={'reader_sha256','decision_sha256'},'Unexpected source fields')
    legacy=value['schema']=='slurm-tracking-readonly-v3'
    check(value['source_before']['reader_sha256']==(LEGACY_READER_SHA if legacy else sha(Path(__file__).read_bytes())),
          'Wrong reader bytes for schema')
    check(value['client_before']==value['client_after'],'Client identity changed')
    client=value['client_before']
    check(set(client)=={'path','sha256','bytes','device','inode','mtime_ns','ctime_ns'} and
          isinstance(client['path'],str) and Path(client['path']).is_absolute() and '..' not in Path(client['path']).parts and
          isinstance(client['sha256'],str) and re.fullmatch('[0-9a-f]{64}',client['sha256']) and
          all(type(client[k]) is int and client[k]>=0 for k in ('bytes','device','inode','mtime_ns','ctime_ns')) and
          0<client['bytes']<=256*1024**2,'Incomplete client provenance')
    check(type(value['observed_at_unix_ns']) is int and value['observed_at_unix_ns']>0 and
          type(value['host']['uid']) is int and value['host']['uid']>=0,'Invalid host/time record')
    check(all(value[k] is False for k in GATES),'Read-only evidence cannot grant execution')
    check(all(type(value[k]) is int and value[k]==0 for k in ('probe_calls','cancellation_calls','submission_calls')),'Unexpected mutating action')
    check(value['analysis']==(_legacy_analyze(value['commands']) if legacy else analyze(value['commands'])),
          'Derived screening differs')
    return value['analysis']

def interpret(value):
    """Validate historical bytes first, then derive current semantics without rewriting."""
    validate(value)
    return analyze(value['commands'])

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    q=sub.add_parser('collect');q.add_argument('--owner-readonly-approved',action='store_true');q.add_argument('--output')
    q=sub.add_parser('inspect');q.add_argument('--input',required=True)
    q=sub.add_parser('interpret');q.add_argument('--input',required=True)
    args=p.parse_args()
    if args.action in ('inspect','interpret'):
        value=(validate if args.action=='inspect' else interpret)(read(args.input))
    else:
        value=collect(owner_readonly_approved=args.owner_readonly_approved)
        if args.output:
            with Path(args.output).open('x') as stream:json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')
    print(json.dumps(value,indent=2,allow_nan=False))

if __name__=='__main__':main()
