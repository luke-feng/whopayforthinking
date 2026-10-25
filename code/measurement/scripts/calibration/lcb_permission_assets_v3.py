"""Pure P asset-lock policy plus read-only rechecks; never execute a dependency."""
import os
from pathlib import Path
import re
import stat

PREFIX = '/apps/site/opt/x86_64_v3/apptainer-1.5.0-hlqnf6rbvgnmd5pa6nkxfofhtrltalh5'
FUSE_PREFIX = '/apps/site/opt/x86_64_v3/libfuse-3.16.2-u5i7uxuc5vnvh3yp5c3dti77b64673qr'
SQUASH_PREFIX = '/apps/site/opt/x86_64_v3/squashfuse-0.6.1-c7hin3cvpial56kkzbofs22gufqmokel'
FIXED = {
    'runtime': (PREFIX+'/bin/apptainer', '91f0cf1b1a1f3031535d178f136aca9e4ca2aca3735fe1834f028cac6e320a0f'),
    'cpu_sif': ('/data/site/www27-assets-20261008/inference.sif', 'dd834f4fe0707a6834cffde61afe42d08b97876e87e12382af2739434762fba2'),
    'starter': (PREFIX+'/libexec/apptainer/bin/starter', '253a058ee3087d125a886a7751b7edb3e166f3b193c06266abbe1ada050b60a8'),
    'apptainer_conf': (PREFIX+'/etc/apptainer/apptainer.conf', 'ed5ba263f800ddc27f15c74946ff0452cb997fdb43990c7ca5b4e488521168e3'),
    'squashfuse_ll': (SQUASH_PREFIX+'/bin/squashfuse_ll', '2f0af6514c8dfb177d1faa3c679af434d61940e8bc436ea2e8d372ad0f699317'),
    'squashfuse': (SQUASH_PREFIX+'/bin/squashfuse', 'c6261c11a18af1bb3c55729e7fc12f79494ba260213233fac760cd9f3ab51ae6'),
}
REQUIRED = {'starter':'executable','apptainer_conf':'configuration',
            'squashfuse_ll':'executable','squashfuse':'executable'}
SETID_PATH = '/usr/bin/fusermount3'
SETID_SHA = 'd278775c1528dd32efc85c2cb322423ee93aa8dcf76aaa595f7022d427910704'
SETID_REASON = 'fixed_OS_dependency_only_libfuse_internal_mount_umount_fallback'
BASE = ('helper','runtime','cpu_sif','build_record')
KEYS = {'schema',*BASE,'runtime_components','runtime_aliases','identities',
        'libfuse_prefix','prefix_fusermount3','setid_exception'}
# Category is selected by code, never by an untrusted lock field. Path/hash
# bindings are checked separately. The full tuples remain in every record.
IDENTITY_FIELDS = {'shared_fs':(1,2,3,5,6,7), 'node_local':(2,5,6)}


def check(ok, why):
    if not ok:
        raise ValueError(why)


def identity(st):
    return [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_mode,st.st_uid,st.st_gid]


def identity_matches(observed, frozen, category):
    check(category in IDENTITY_FIELDS, 'Unknown P identity category')
    def valid(value):
        return (type(value) is list and len(value)==8
                and all(type(n) is int and n>=0 for n in value)
                and value[1]>0 and value[2]>0 and value[5]<=0xffff)
    return (valid(observed) and valid(frozen)
            and all(observed[i]==frozen[i] for i in IDENTITY_FIELDS[category]))


def snapshot(lock):
    """Current-node full identities, retained only to bracket one operation."""
    refs={**{n:lock[n] for n in BASE},**lock['runtime_components']}
    return {'identities':{name:identity(Path(row['path']).lstat()) for name,row in refs.items()},
            'aliases':{name:identity(Path(row['path']).lstat()) for name,row in lock['runtime_aliases'].items()},
            'conditional':identity(Path(SETID_PATH).lstat())}


def verify_same_run(before, after):
    """These two reads belong to ONE run, not to prepare versus run."""
    check(before==after, 'P dependencies changed within run')


def literal(value):
    check(type(value) is str and Path(value).is_absolute() and str(Path(value))==value
          and '..' not in Path(value).parts and not any(c in value for c in (':',',','\n','\r','\0')),
          'Literal P asset path required')
    return value


def ref(row):
    check(type(row) is dict and set(row)=={'path','sha256'}, 'Exact P reference required')
    literal(row['path'])
    check(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'P digest required')


def metadata(value, *, owner, executable=False, setid=False):
    check(type(value) is list and len(value)==8 and all(type(n) is int and n>=0 for n in value),
          'P identity must be eight integers')
    device,inode,size,mtime,ctime,mode,uid,gid=value
    check(inode>0 and size>0 and size<=256*1024**2 and 0<=mode<=0xffff and uid==owner and stat.S_ISREG(mode)
          and not mode&0o022 and (mode&0o6000==0o4000 if setid else not mode&0o6000),
          'P component owner/type/mode/size')
    if executable:
        check(mode&0o111, 'P component not executable')


def validate(lock, owner_uid):
    """No filesystem reads and no issuance: validate the entire declared graph."""
    check(type(lock) is dict and set(lock)==KEYS and lock['schema']=='permission-normal-assets-v3',
          'P activation requires final assets-v3, not legacy or a template')
    check(type(owner_uid) is int and owner_uid>0, 'P owner uid')
    for name in BASE:
        ref(lock[name])
    refs=lock['runtime_components'];ids=lock['identities']
    check(type(refs) is dict and set(REQUIRED)<=set(refs) and len(refs)<=32
          and type(ids) is dict and set(ids)==set(BASE)|set(refs), 'Complete P component identities required')
    for name,row in refs.items():
        check(re.fullmatch('[a-z][a-z0-9_]{0,47}',name) and type(row) is dict
              and set(row)=={'path','sha256','kind'} and row['kind'] in ('executable','configuration','library')
              and row['kind']==REQUIRED.get(name,row['kind']), 'P component kind/keys')
        ref({k:row[k] for k in ('path','sha256')})
        metadata(ids[name],owner=0,executable=row['kind']=='executable')
    for name,expected in FIXED.items():
        row=lock[name] if name in BASE else refs[name]
        check((row['path'],row['sha256'])==expected, 'Frozen P site asset differs: '+name)
    metadata(ids['runtime'],owner=0,executable=True)
    metadata(ids['helper'],owner=owner_uid,executable=True)
    metadata(ids['build_record'],owner=owner_uid)
    check(ids['helper'][2]<=8*1024**2 and ids['build_record'][2]<=2*1024**2,
          'P helper/build record byte bound')
    for name,row in refs.items():
        check(ids[name][2] <= (64*1024**2 if row['kind']=='executable' else 128*1024**2),
              'P executable/configuration/library byte bound')
    sif=ids['cpu_sif']
    check(type(sif) is list and len(sif)==8 and all(type(n) is int and n>=0 for n in sif)
          and sif[1]==4402469546366 and sif[2]==8011186176
          and sif[5]==stat.S_IFREG|0o644 and sif[6]==owner_uid, 'Frozen SIF identity/mode differs')
    check(lock['libfuse_prefix']==FUSE_PREFIX, 'Frozen libfuse prefix differs')
    libraries={name for name,row in refs.items() if row['kind']=='library'}
    check(libraries, 'No libfuse shared library locked')
    for name in libraries:
        path=Path(refs[name]['path'])
        check(str(path.parent) in (FUSE_PREFIX+'/lib',FUSE_PREFIX+'/lib64')
              and re.fullmatch(r'libfuse3\.so(?:\.[0-9]+)*',path.name), 'Library outside libfuse prefix')
    aliases=lock['runtime_aliases']
    check(type(aliases) is dict and {'squashfuse_ll','squashfuse'}<=set(aliases) and len(aliases)<=32,
          'Both squashfs aliases required')
    for name,row in aliases.items():
        check(type(row) is dict and set(row)=={'path','link_target','component'}
              and row['component'] in refs and type(row['link_target']) is str
              and '\0' not in row['link_target'] and '\n' not in row['link_target'], 'P alias reference')
        literal(row['path'])
        if name in ('squashfuse_ll','squashfuse'):
            check(row['path']==PREFIX+'/libexec/apptainer/bin/'+name and row['component']==name,
                  'Squashfs alias path/role differs')
        else:
            path=Path(row['path'])
            check(row['component'] in libraries and str(path.parent) in (FUSE_PREFIX+'/lib',FUSE_PREFIX+'/lib64')
                  and re.fullmatch(r'libfuse3\.so(?:\.[0-9]+)*',path.name), 'Library alias outside prefix')
        target=Path(row['link_target'])
        target=target if target.is_absolute() else Path(row['path']).parent/target
        by_path={r['path']:r for r in aliases.values()}
        seen=set()
        while str(target) in by_path:
            check(str(target) not in seen and len(seen)<32, 'Alias cycle')
            seen.add(str(target));next_row=by_path[str(target)]
            next_target=Path(next_row['link_target'])
            target=next_target if next_target.is_absolute() else target.parent/next_target
        check('..' not in target.parts and str(target)==refs[row['component']]['path'], 'Alias target differs')
    optional=lock['prefix_fusermount3']
    check(type(optional) is dict and optional.get('path')==FUSE_PREFIX+'/bin/fusermount3', 'Prefix helper path')
    if optional.get('status')=='absent':
        check(set(optional)=={'path','status','errno'} and optional['errno']=='ENOENT'
              and 'prefix_fusermount3' not in refs, 'Explicit absent prefix helper required')
    else:
        check(optional=={'path':FUSE_PREFIX+'/bin/fusermount3','status':'present'}
              and refs.get('prefix_fusermount3',{}).get('path')==optional['path']
              and refs['prefix_fusermount3']['kind']=='executable', 'Present prefix helper not locked')
    special=lock['setid_exception']
    check(type(special) is dict and set(special)=={'path','sha256','identity','reason','direct_execution'}
          and special['path']==SETID_PATH and special['sha256']==SETID_SHA
          and special['reason']==SETID_REASON and special['direct_execution'] is False,
          'Only fixed OS/libfuse conditional setid dependency is approved')
    metadata(special['identity'],owner=0,executable=True,setid=True)
    check(stat.S_IMODE(special['identity'][5])==0o4755, 'Conditional dependency must retain 04755')
    declared=[lock[n]['path'] for n in BASE]+[r['path'] for r in refs.values()]+[r['path'] for r in aliases.values()]+[SETID_PATH]
    check(len(set(declared))==len(declared), 'P asset graph path aliases not explicit/unique')
    return refs


def assemble(inventory, helper_ref, helper_identity, build_ref, build_identity, owner_uid):
    """Pure candidate assembly from real read receipts; missing is never filled."""
    check(inventory.get('schema')=='P-activation-readonly-assets-v1', 'P readonly inventory required')
    records=inventory['records']
    by_role={r['role']:r for r in records if r['role']!='libfuse3_object'}
    check(len(by_role)==sum(r['role']!='libfuse3_object' for r in records)
          and set(by_role)=={'frontend','starter','apptainer_conf','squashfuse_ll_alias',
              'squashfuse_alias','prefix_fusermount3','os_fusermount3','cpu_sif'}, 'Asset receipt roster differs')
    directories=inventory['library_directories']
    check(len(directories)==2 and {r['path'] for r in directories}=={FUSE_PREFIX+'/lib',FUSE_PREFIX+'/lib64'},
          'Library directory receipts missing')
    listed=set()
    for directory in directories:
        if directory['status']=='read':
            check(directory['before']==directory['after'] and directory['before']['uid']==0
                  and directory['before']['file_type']==stat.S_IFDIR and not directory['before']['mode']&0o022,
                  'Library directory changed or unsafe')
            check(directory['entries']==sorted(set(directory['entries']))
                  and all(re.fullmatch(r'libfuse3\.so(?:\.[0-9]+)*',n) for n in directory['entries']),
                  'Library entry list differs')
            listed|={directory['path']+'/'+name for name in directory['entries']}
        else:
            check(directory['error'].startswith('FileNotFoundError: [Errno 2]'), 'Unidentified library directory')
    check(listed=={r['path'] for r in records if r['role']=='libfuse3_object'}, 'Library receipt coverage differs')
    def good(row):
        check(row['status']=='read' and row['error'] is None and row['before']==row['after'],
              'Missing or unstable P asset receipt')
        info=row['before']
        check(row['bytes_read']==info['bytes'], 'P asset read incomplete')
        return [info['device'],info['inode'],info['bytes'],info['mtime_ns'],info['ctime_ns'],
                info['file_type']|info['mode'],info['uid'],info['gid']]
    lock={'schema':'permission-normal-assets-v3','helper':helper_ref,'build_record':build_ref,
          'runtime_components':{},'runtime_aliases':{},'identities':{'helper':helper_identity,'build_record':build_identity},
          'libfuse_prefix':FUSE_PREFIX}
    roles={'runtime':'frontend','cpu_sif':'cpu_sif','starter':'starter','apptainer_conf':'apptainer_conf',
           'squashfuse_ll':'squashfuse_ll_alias','squashfuse':'squashfuse_alias'}
    for name,role in roles.items():
        r=by_role[role];meta=good(r)
        refrow={'path':r['realpath'],'sha256':r['sha256']}
        lock['identities'][name]=meta
        if name in BASE:
            lock[name]=refrow
        else:
            lock['runtime_components'][name]={**refrow,'kind':REQUIRED[name]}
        if name.startswith('squashfuse'):
            check(r['lstat']['file_type']==stat.S_IFLNK and r['lstat']['uid']==0
                  and r['symlink_target'], 'Squash alias receipt missing')
            lock['runtime_aliases'][name]={'path':r['path'],'link_target':r['symlink_target'],'component':name}
    targets={}
    for r in records:
        if r['role']!='libfuse3_object':
            continue
        meta=good(r);path=r['realpath']
        if path not in targets:
            key='libfuse3_library_'+str(len(targets));targets[path]=key
            lock['runtime_components'][key]={'path':path,'sha256':r['sha256'],'kind':'library'}
            lock['identities'][key]=meta
        key=targets[path]
        check(lock['runtime_components'][key]['sha256']==r['sha256'] and lock['identities'][key]==meta,
              'Library aliases disagree on target')
        if r['lstat']['file_type']==stat.S_IFLNK:
            name=Path(r['path']).name.replace('.','_')
            lock['runtime_aliases'][name]={'path':r['path'],'link_target':r['symlink_target'],'component':key}
    optional=by_role['prefix_fusermount3']
    if optional['status']=='unavailable':
        check(optional['error'].startswith('FileNotFoundError: [Errno 2]'), 'Unknown prefix helper absence')
        lock['prefix_fusermount3']={'path':optional['path'],'status':'absent','errno':'ENOENT'}
    else:
        meta=good(optional)
        check(optional['realpath']==optional['path'], 'Prefix helper alias not approved')
        lock['prefix_fusermount3']={'path':optional['path'],'status':'present'}
        lock['runtime_components']['prefix_fusermount3']={'path':optional['path'],'sha256':optional['sha256'],'kind':'executable'}
        lock['identities']['prefix_fusermount3']=meta
    special=by_role['os_fusermount3'];meta=good(special)
    check(special['realpath']==special['path'], 'OS conditional dependency alias not approved')
    lock['setid_exception']={'path':special['path'],'sha256':special['sha256'],'identity':meta,
                             'reason':SETID_REASON,'direct_execution':False}
    validate(lock,owner_uid)
    return lock


def _parents(path, owner_uid):
    check(path.is_absolute() and path.parent.resolve(strict=True)==path.parent, 'Canonical parent chain required')
    for parent in path.parents:
        info=parent.lstat()
        check(info.st_uid in (0,owner_uid) and stat.S_ISDIR(info.st_mode)
              and not info.st_mode&0o022, 'Unsafe P dependency parent')


def recheck(lock, owner_uid, reader, *, deadline_ns, base_already_hashed, initial_snapshot=None):
    """Only file reads. reader is the P held-fd streaming function, not JSON."""
    refs=validate(lock,owner_uid)
    check(base_already_hashed is True, 'Base hashes must be checked in this run first')
    initial=snapshot(lock) if initial_snapshot is None else initial_snapshot
    observed_identities={};observed_aliases={}
    for name,row in {**{n:lock[n] for n in BASE},**refs}.items():
        path=Path(row['path']);_parents(path,owner_uid)
        info=identity(path.lstat());observed_identities[name]=info
        check(path.resolve(strict=True)==path and identity_matches(info,lock['identities'][name],'shared_fs'),
              'P declared dependency identity changed: '+name)
    for name,row in lock['runtime_aliases'].items():
        path=Path(row['path']);_parents(path,owner_uid)
        before=path.lstat()
        check(stat.S_ISLNK(before.st_mode) and before.st_uid==0 and os.readlink(path)==row['link_target']
              and str(path.resolve(strict=True))==refs[row['component']]['path']
              and identity(before)==identity(path.lstat()), 'P dependency alias changed: '+name)
        observed_aliases[name]={'path':str(path),'link_target':os.readlink(path),
                               'component':row['component'],'identity':identity(before)}
        check(observed_aliases[name]['link_target']==row['link_target'], 'Alias changed after check')
    declared={r['path'] for r in refs.values() if r['kind']=='library'}
    declared|={r['path'] for r in lock['runtime_aliases'].values() if r['component'] in refs
               and refs[r['component']]['kind']=='library'}
    observed=set()
    for directory in (Path(FUSE_PREFIX)/'lib',Path(FUSE_PREFIX)/'lib64'):
        try:
            before=directory.lstat();_parents(directory,owner_uid)
        except FileNotFoundError as exc:
            check(exc.errno==2, 'Unknown library absence');continue
        check(stat.S_ISDIR(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022,
              'Unsafe library directory')
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name.startswith('libfuse3.so'):
                    check(len(observed)<64, 'Library roster bound')
                    observed.add(str(directory/entry.name))
        check(identity(before)==identity(directory.lstat()), 'Library directory changed')
    check(observed==declared, 'libfuse shared-object roster differs')
    optional=lock['prefix_fusermount3']
    if optional['status']=='absent':
        try:
            Path(optional['path']).lstat()
        except FileNotFoundError as exc:
            check(exc.errno==2, 'Unknown prefix helper absence')
        else:
            raise ValueError('Previously absent prefix fusermount3 now exists')
    # This is NOT the generic executable verifier and has no execution call.
    # Its exception cannot apply to a different path, hash, uid or mode.
    special=lock['setid_exception'];path=Path(special['path']);_parents(path,owner_uid)
    record,info,_=reader(path,256*1024**2,deadline_ns=deadline_ns)
    check(path.resolve(strict=True)==path and record['sha256']==SETID_SHA
          and identity_matches(identity(info),special['identity'],'node_local'), 'Conditional setid dependency changed')
    point={'identities':observed_identities,
           'aliases':{name:row['identity'] for name,row in observed_aliases.items()},'conditional':identity(info)}
    check(initial==point==snapshot(lock), 'P identities changed within this recheck')
    return {'status':'P-dependencies-rechecked-not-executed','direct_dependency_execution':False,
            'identities':observed_identities,'aliases':observed_aliases,'library_roster':sorted(observed),
            'conditional_dependency':{'record':record,'identity':identity(info)},
            'initial_snapshot':initial,'final_snapshot':point,
            'prefix_fusermount3':dict(optional)}


def verify_receipt(lock, receipt):
    """Offline receipt join, never opens original machine paths."""
    check(receipt['status']=='P-dependencies-rechecked-not-executed'
          and receipt['direct_dependency_execution'] is False
          and set(receipt['identities'])==set(lock['identities'])
          and all(identity_matches(receipt['identities'][name],frozen,'shared_fs')
                  for name,frozen in lock['identities'].items()), 'P dependency receipt identities')
    check(set(receipt['aliases'])==set(lock['runtime_aliases']), 'Alias receipt roster')
    for name,row in lock['runtime_aliases'].items():
        seen=receipt['aliases'][name]
        check(type(seen['identity']) is list and len(seen['identity'])==8
              and all(type(n) is int and n>=0 for n in seen['identity'])
              and {k:seen[k] for k in row}==row and seen['identity'][6]==0
              and stat.S_ISLNK(seen['identity'][5]), 'Alias receipt binding')
    libraries={r['path'] for r in lock['runtime_components'].values() if r['kind']=='library'}
    libraries|={r['path'] for r in lock['runtime_aliases'].values()
                if lock['runtime_components'][r['component']]['kind']=='library'}
    check(receipt['library_roster']==sorted(libraries), 'Library receipt roster')
    dep=receipt['conditional_dependency']
    check(identity_matches(dep['identity'],lock['setid_exception']['identity'],'node_local')
          and dep['record']=={'path':SETID_PATH,'sha256':SETID_SHA,'bytes':dep['identity'][2]}
          and receipt['prefix_fusermount3']==lock['prefix_fusermount3'], 'Conditional dependency receipt binding')
    point={'identities':receipt['identities'],
           'aliases':{name:row['identity'] for name,row in receipt['aliases'].items()},
           'conditional':dep['identity']}
    check(receipt['initial_snapshot']==receipt['final_snapshot']==point,
          'P receipt identities changed within this recheck')
