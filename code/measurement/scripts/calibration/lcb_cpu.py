"""Case-local cgroup v2 CPU accounting. Tests use virtual files only."""
from fractions import Fraction as F
import os
from pathlib import Path
import re
import uuid

CGROOT = Path('/sys/fs/cgroup')


def cpus(text):
    result=set()
    for part in text.strip().split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?',part): raise ValueError('Invalid CPU set')
        pair=list(map(int,part.split('-')));lo,hi=pair[0],pair[-1]
        if hi<lo or hi>1048576: raise ValueError('Invalid CPU range')
        result.update(range(lo,hi+1))
    if not result: raise ValueError('Empty CPU set')
    return result


def identity(path):
    st=Path(path).stat()
    return {'device':st.st_dev,'inode':st.st_ino}


def usage(path):
    try:
        rows=dict(line.split() for line in (Path(path)/'cpu.stat').read_text().splitlines())
        raw=rows['usage_usec']
        if not raw.isdigit(): raise ValueError('Invalid usage_usec')
        return {'usage_usec':int(raw),'error':None}
    except (OSError,KeyError,ValueError) as exc:
        return {'usage_usec':None,'error':type(exc).__name__+': '+str(exc)}


def cpu_record(lower, wall, before=None, after=None, *, single_cpu_verified):
    if single_cpu_verified is not True: raise ValueError('A hard one-CPU cpuset is required for the wall-time upper bound')
    if isinstance(lower,bool) or isinstance(wall,bool):raise ValueError('Numeric CPU observations required')
    reported=F(str(lower));elapsed=F(str(wall))
    low=F((reported*1000000).__floor__(),1000000)
    if reported<0 or elapsed<0: raise ValueError('Nonnegative CPU usage and elapsed time required')
    # Outward microsecond rounding matches cpu.stat's resolution.
    scaled=elapsed*1000000;upper=F(-(-scaled.numerator//scaled.denominator),1000000)
    if low>upper: raise ValueError('Reaped CPU exceeds verified CPU-times-wall upper bound')
    measured=None
    if (before is None)!=(after is None):raise ValueError('Incomplete cgroup lifecycle evidence')
    if before is not None and after is not None:
        if (before['identity']!=after['identity'] or before['path']!=after['path']
            or before['empty'] is not True or after['empty'] is not True):
            raise ValueError('Case cgroup identity or exclusive lifecycle changed')
        a,b=before['usage']['usage_usec'],after['usage']['usage_usec']
        if any(x is not None and (type(x) is not int or x<0) for x in (a,b)):raise ValueError('Invalid CPU counter')
        if a is not None and b is not None:
            if b<a: raise ValueError('CPU counter decreased')
            measured=F(b-a,1000000)
            if not low<=measured<=upper: raise ValueError('Measured CPU inconsistent with case bounds')
    return {'schema':'verifier-cpu-v1','status':'measured' if measured is not None else 'unidentified',
        'verifier_cpu_seconds_measured':None if measured is None else str(measured),
        'reported_child_cpu_s':str(reported), 'reaped_cpu_lower_bound_s':str(low),
        'nominal_one_cpu_limit_times_wall_s':str(upper),
        'cpu_seconds_bounds':[str(measured),str(measured)] if measured is not None else [str(low),str(upper)],
        'wall_seconds':str(elapsed),'hard_cpu_count':1,'before':before,'after':after,
        'scope':'case container/launcher cgroup; expected-answer comparison stays in the host; bounds are not a point estimate'}


def total_cpu(records):
    if any(r.get('schema')!='verifier-cpu-v1' for r in records): raise ValueError('Missing CPU accounting record')
    for r in records:
        before,after=r.get('before'),r.get('after')
        rebuilt=cpu_record(r['reported_child_cpu_s'],r['wall_seconds'],before,after,
                           single_cpu_verified=type(r.get('hard_cpu_count')) is int and r['hard_cpu_count']==1)
        if any(r.get(k)!=v for k,v in rebuilt.items()):
            raise ValueError('CPU record cannot be reproduced from its observations')
    lo=sum((F(r['cpu_seconds_bounds'][0]) for r in records),F(0))
    hi=sum((F(r['cpu_seconds_bounds'][1]) for r in records),F(0))
    known=all(r['verifier_cpu_seconds_measured'] is not None for r in records)
    return {'verifier_cpu_seconds_measured':str(lo) if known else None,
            'verifier_cpu_seconds_bounds':[str(lo),str(hi)],'cases':len(records),
            'verifier_cpu_status':'measured' if known else 'unidentified'}


class CaseCgroup:
    """Create only a unique leaf under an explicitly delegated owner subtree.

    Never enable controllers on the parent or kill/move existing processes.
    A populated/changed leaf is retained and reported instead of sweeping it.
    """
    def __init__(self,policy,cpu):
        self.path=None;self.before=None
        if policy.get('mode')=='bounds': return
        if policy.get('mode')!='delegated_cgroup_v2' or policy.get('delegation_authorized') is not True:
            raise ValueError('Explicit delegated-cgroup approval required')
        if not policy.get('delegation_reference'): raise ValueError('Delegation reference required')
        raw=Path(policy['root']);root=raw.resolve(strict=True)
        current=next(x.split('::',1)[1] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
        parent=CGROOT/current.lstrip('/')
        if raw!=root or root==parent or not root.is_relative_to(parent) or not root.name.startswith('www27-'):
            raise ValueError('Dedicated materialized subtree below the caller cgroup required')
        if root.stat().st_uid!=os.getuid() or (root/'cgroup.procs').read_text().strip():
            raise ValueError('Delegated parent must be owner-owned and empty')
        if cpu not in cpus((root/'cpuset.cpus.effective').read_text()): raise ValueError('CPU outside delegation')
        path=root/('www27-case-'+uuid.uuid4().hex);path.mkdir()
        self.path=path;self.ident=identity(path)
        try:
            for name,value in {'cpu.max':'100000 100000','memory.max':'1073741824','pids.max':'32',
                    'cpuset.mems':(root/'cpuset.mems.effective').read_text().strip(),'cpuset.cpus':str(cpu)}.items():
                (path/name).write_text(value)
            self.before=self.snapshot()
            if not self.before['empty']: raise ValueError('New case cgroup is not empty')
        except BaseException:
            self.cleanup();raise

    def snapshot(self):
        if identity(self.path)!=self.ident: raise ValueError('Case cgroup replaced')
        events=dict(line.split() for line in (self.path/'cgroup.events').read_text().splitlines())
        if events.get('populated') not in ('0','1'): raise ValueError('Missing populated state')
        return {'identity':self.ident,'path':str(self.path),'empty':events['populated']=='0',
                'usage':usage(self.path)}

    def cleanup(self):
        if self.path is None: return
        if not self.snapshot()['empty']: raise ValueError('Case cgroup still populated; retain and stop: '+str(self.path))
        self.path.rmdir()  # Only the unique empty leaf created by this instance.
