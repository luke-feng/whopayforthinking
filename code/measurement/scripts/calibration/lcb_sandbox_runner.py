"""Trusted helper to run INSIDE a reviewed CPU-only Apptainer image.

Expected answers never enter this process/container. Worker tests must not call
run_candidate or functional_child; those execute owner-provided candidate code.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import runpy
import selectors
import signal
import subprocess
import sys
import time


MAX_IO=65536


def namespace_ids():
    result={}
    for key in ('pid','net','mnt'):
        try:result[key]=os.readlink('/proc/self/ns/'+key)
        except OSError:result[key]=None
    return result


def probe():
    sensitive={}
    for p in ('/home','/scratch','/shares','/apps'):
        try:
            # Empty dummy directories are acceptable; never read file contents.
            entries=list(Path(p).iterdir()) if Path(p).exists() else []
            sensitive[p]=any(not x.is_dir() or any(x.iterdir()) for x in entries)
        except OSError:sensitive[p]=True  # Unknown visibility is not verified isolation.
    limits={};cg_identity=None;cpu_usage=None;cpu_error=None
    try:
        line=next(x for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
        rel=line.split('::',1)[1].lstrip('/')
        if '..' in Path(rel).parts:raise ValueError('Invalid cgroup path')
        base=Path('/sys/fs/cgroup')/rel
        for key in ('memory.max','pids.max','cpu.max','cpuset.cpus.effective'):
            limits[key]=(base/key).read_text().strip()
        st=base.stat();cg_identity={'device':st.st_dev,'inode':st.st_ino}
        try:
            stats=dict(line.split() for line in (base/'cpu.stat').read_text().splitlines())
            cpu_usage=int(stats['usage_usec'])
        except (OSError,ValueError,KeyError) as exc:cpu_error=type(exc).__name__+': '+str(exc)
    except (OSError,ValueError,StopIteration):limits={}
    cg_readonly=False
    try:
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            fields=line.split()
            if fields[4]=='/sys/fs/cgroup':cg_readonly='ro' in fields[5].split(',')
    except OSError:pass
    return {'schema':'lcb-sandbox-probe-v1','uid':os.getuid(),'namespaces':namespace_ids(),
            'network_interfaces':sorted(x.name for x in Path('/sys/class/net').iterdir()),
            'sensitive_nonempty':sensitive,'cgroup_limits':limits,'cgroup_mount_readonly':cg_readonly,
            'cgroup_identity':cg_identity,'cpu_stat_usage_usec':cpu_usage,'cpu_stat_error':cpu_error}


def child_limits():
    resource.setrlimit(resource.RLIMIT_CPU,(3,4))
    resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024,1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))


def verify_probe(result,host_namespaces,expected_cpu=None,expected_cgroup=None):
    if result.get('schema')!='lcb-sandbox-probe-v1' or type(result.get('uid')) is not int or result['uid']<=0:
        raise ValueError('Invalid non-root probe')
    for key in ('pid','net','mnt'):
        actual=result.get('namespaces',{}).get(key)
        if not actual or not host_namespaces.get(key) or actual==host_namespaces[key]:
            raise ValueError('Namespace isolation not verified: '+key)
    if result.get('network_interfaces')!=['lo']:raise ValueError('Loopback-only network not verified')
    if set(result.get('sensitive_nonempty',{}))!={'/home','/scratch','/shares','/apps'} or any(result['sensitive_nonempty'].values()):
        raise ValueError('Sensitive filesystem visibility not excluded')
    limits=result.get('cgroup_limits',{})
    try:
        memory=int(limits['memory.max']);pids=int(limits['pids.max'])
        quota,period=map(int,limits['cpu.max'].split())
    except (ValueError,KeyError,TypeError):raise ValueError('Finite delegated cgroup limits not observed')
    if not 0<memory<=1073741824 or not 0<pids<=32 or not 0<quota<=period:
        raise ValueError('Resource limits exceed approved envelope')
    cpu=limits.get('cpuset.cpus.effective','')
    if not cpu.isdigit() or (expected_cpu is not None and int(cpu)!=expected_cpu):
        raise ValueError('A hard single allocated CPU cpuset was not verified')
    if expected_cgroup is not None and result.get('cgroup_identity')!=expected_cgroup:
        raise ValueError('Container escaped the reserved case cgroup')
    if result.get('cgroup_mount_readonly') is not True:raise ValueError('Cgroup controls must not be writable inside')


def functional_child(entry):
    if not Path('/.singularity.d').is_dir():raise ValueError('Functional helper is container-only')
    if not entry.isidentifier() or entry.startswith('__'):raise ValueError('Invalid entry')
    args=[json.loads(line) for line in sys.stdin.read().splitlines() if line.strip()]
    import contextlib
    with contextlib.redirect_stdout(sys.stderr):
        mod=runpy.run_path('/candidate/program.py',run_name='candidate_module')
        target=mod['Solution']() if 'Solution' in mod else None
        function=getattr(target,entry) if target is not None else mod[entry]
        answer=function(*args)
    print(json.dumps(answer,allow_nan=False))


def run_candidate(mode,entry,host_namespaces):
    data=sys.stdin.buffer.read(16*1024*1024+1)
    if len(data)>16*1024*1024:raise ValueError('Input limit exceeded')
    command=[sys.executable,'-I','-B','/candidate/program.py'] if mode=='stdin' else [
        sys.executable,'-I','-B',__file__,'--functional-child',entry,
        '--host-namespaces',json.dumps(host_namespaces)]
    before=resource.getrusage(resource.RUSAGE_CHILDREN);started=time.monotonic()
    child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           preexec_fn=child_limits,start_new_session=True)
    selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};sent=0;status='ok'
    for stream,key in ((child.stdout,'stdout'),(child.stderr,'stderr')):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,key)
    if data:
        os.set_blocking(child.stdin.fileno(),False);selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
    else:child.stdin.close()
    code=None
    try:
        while selector.get_map():
            if time.monotonic()-started>5:status='time_limit';break
            for key,_ in selector.select(.05):
                if key.data=='stdin':
                    try:sent+=os.write(key.fd,data[sent:sent+65536])
                    except BrokenPipeError:sent=len(data)
                    if sent==len(data):selector.unregister(key.fileobj);key.fileobj.close()
                else:
                    piece=os.read(key.fd,8192)
                    if not piece:selector.unregister(key.fileobj);key.fileobj.close()
                    else:
                        buffers[key.data].extend(piece)
                        if len(buffers[key.data])>MAX_IO:status='output_limit';break
            if status!='ok':break
        if status=='ok':
            try:code=child.wait(timeout=max(.001,5-(time.monotonic()-started)))
            except subprocess.TimeoutExpired:status='time_limit'
    finally:
        # Kill only this case's process group, including lingering descendants.
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        final_code=child.wait(timeout=2)
        if code is None:code=final_code
        selector.close()
        for stream in (child.stdin,child.stdout,child.stderr):
            if not stream.closed:stream.close()
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    if status=='ok' and code!=0:status='runtime_error'
    return {'schema':'lcb-case-result-v1','status':status,'returncode':code,
            'stdout':bytes(buffers['stdout'][:MAX_IO]).decode('utf-8',errors='replace'),
            'stderr':bytes(buffers['stderr'][:MAX_IO]).decode('utf-8',errors='replace'),
            'child_wall_s':time.monotonic()-started,
            'reaped_child_cpu_s':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
            'cpu_scope':'reaped child processes, not full-container accounting'}


def main():
    p=argparse.ArgumentParser();p.add_argument('--probe',action='store_true')
    p.add_argument('--mode',choices=('stdin','functional'));p.add_argument('--entry',default='')
    p.add_argument('--functional-child');p.add_argument('--host-namespaces')
    p.add_argument('--cpu-id',type=int);p.add_argument('--expected-cgroup-identity');a=p.parse_args()
    if a.probe:result=probe()
    elif a.functional_child:
        verify_probe(probe(),json.loads(a.host_namespaces or '{}'))
        return functional_child(a.functional_child)
    elif a.mode:
        # Probe and check INSIDE the very same container before running code.
        inspection=probe();verify_probe(inspection,json.loads(a.host_namespaces or '{}'),a.cpu_id,
                                       json.loads(a.expected_cgroup_identity) if a.expected_cgroup_identity else None)
        result=run_candidate(a.mode,a.entry,json.loads(a.host_namespaces));result['isolation_probe']=inspection
    else:raise ValueError('Explicit operation required')
    print(json.dumps(result,allow_nan=False))


if __name__=='__main__':main()
