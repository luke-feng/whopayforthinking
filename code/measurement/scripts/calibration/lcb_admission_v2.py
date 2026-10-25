"""Read-only three-stage decisions and unapproved third-stage config proposals.

Legacy v1 receipts are preserved, never relabelled as v2. Legacy records are
loaded by verified 3028455 Git sources; new records require current source hashes.
No GPU/container/model/candidate execution. This is not an execution launcher.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from pilot import read_json, write_new
from lcb_sandbox import file_sha
from lcb_cap_policy import POLICY, STAGES, envelope, select, generation_timeout

ROOT = Path(__file__).resolve().parents[2]
LEGACY_SHA = '3028455927950c538e673b1b30768c33a5201780'
SCHEMA = 'lcb-model-cap-recommendation-v2'
DATA_FILES = ('data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json',
              'data/calibration/lcb-generation-seeds-v1.proposal.json',
              'data/calibration/model-panel-theory-aligned-v2.json',
              'experiments/calibration/lcb-lifecycle-acceptance.template.json')


def blob(path):
    return subprocess.check_output(['git', '-C', str(ROOT), 'show', LEGACY_SHA+':'+path])


def legacy_hashes():
    tree = ast.parse(blob('scripts/calibration/lcb_collector.py'))
    node = next(n for n in tree.body if isinstance(n,ast.Assign) and any(
        isinstance(t,ast.Name) and t.id=='SOURCE_FILES' for t in n.targets))
    names = ast.literal_eval(node.value)
    return {n:hashlib.sha256(blob('scripts/calibration/'+n)).hexdigest() for n in names}


def verify_legacy_source(source):
    if not source:
        raise ValueError('Supply the verified 3028455 checkout/snapshot for legacy evidence')
    source = Path(source).resolve(strict=True)
    paths = subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-r','--name-only',LEGACY_SHA,
                                     'scripts/calibration'],text=True).splitlines()
    py = {p for p in paths if p.endswith('.py')}
    entries=list((source/'scripts/calibration').rglob('*'))
    actual={str(p.relative_to(source)) for p in entries if p.is_file()}
    # -B prevents writing, not reading, bytecode. Do not admit unverified .pyc,
    # extension modules, or symlinked dependencies into the historical loader.
    if any(p.is_symlink() for p in entries) or not py <= actual or actual-set(paths):
        raise ValueError('Historical Python source coverage differs')
    for name in sorted(actual | set(DATA_FILES)):
        p = source/name
        if any(x.is_symlink() for x in (p,*p.parents)) or p.read_bytes()!=blob(name):
            raise ValueError('Historical source/data pin changed: '+name)
    return source


def load_stage(path, legacy_source=None):
    from lcb_collector import source_hashes
    from lcb_admission_report import load_run
    path = Path(path).resolve(strict=True)
    meta = read_json(path/'run.json'); cfg = meta['config']
    if meta.get('source_files_sha256') == source_hashes():
        result = load_run(path)
        result['verified_source'] = 'current_recorded_hashes'
        return result
    if (cfg.get('max_tokens') not in (4096,8192,12288) or cfg.get('max_model_len')!=16384
            or meta.get('source_files_sha256')!=legacy_hashes()):
        raise ValueError('Unrecognized historical source or impossible legacy envelope')
    source = verify_legacy_source(legacy_source)
    code = '''import json,sys
sys.path.insert(0,sys.argv[1])
from lcb_admission_report import load_run
print(json.dumps(load_run(sys.argv[2]),allow_nan=False))
'''
    raw = subprocess.check_output([sys.executable,'-I','-B','-c',code,
                                   str(source/'scripts/calibration'),str(path)],timeout=120)
    result = json.loads(raw); result['verified_source'] = LEGACY_SHA
    return result


def choose(records):
    if not records or len(records)>3:
        raise ValueError('One stratum, at most three complete stages')
    records = sorted(records,key=lambda r:r['cfg']['max_tokens'])
    first = records[0]; name = first['cfg']['stratum_id']; stages = {}
    common = dict(first['signature']); common.pop('max_model_len',None)
    for r in records:
        cfg = r['cfg']; cap = cfg['max_tokens']
        signature = dict(r['signature']); signature.pop('max_model_len',None)
        if (cfg['stratum_id']!=name or signature!=common or r['tokenization_rows']!=first['tokenization_rows']
                or r['lengths']!=first['lengths']):
            raise ValueError('Keep models, seeds, native prompt IDs and all non-context settings paired')
        if cfg['max_model_len']!=envelope(name,cap) or cap in stages:
            raise ValueError('Duplicate or non-preregistered cap/context pair')
        if cfg.get('generation_timeout_s')!=generation_timeout(cap):
            raise ValueError('Keep the preregistered per-stage generation deadline')
        if max(r['lengths'].values())+cap>cfg['max_model_len']:
            raise ValueError('Full workload context fit failed')
        stages[cap]=r['samples']
    if name in ('coder-nonthinking','q38-nonthinking'):
        if len(records)!=1:
            raise ValueError('Control cap is fixed/inherited, not optimized')
        cap=first['cfg']['max_tokens']
        return {'status':'cap_recommended','max_tokens':cap,'max_model_len':envelope(name,cap),
                'observed_truncation':{cap:{'truncated':sum(s['truncated'] for s in first['samples']),'candidates':128}},
                'control_rule':'fixed_4096' if name=='coder-nonthinking' else 'inherit_on_cap_and_context',
                'next_max_tokens':None,'next_max_model_len':None}
    return select(stages,list(first['lengths'].values()))


def report(paths, legacy_source=None):
    records = [load_stage(p,legacy_source) for p in paths]
    records.sort(key=lambda r:r['cfg']['max_tokens'])
    result = choose(records)
    value = {'schema':SCHEMA,'cap_policy':POLICY,**result,
        'rule_reference':'review/q38-cap8192-7201132-review.md',
        'stratum_id':records[0]['cfg']['stratum_id'],
        'frozen_workload_sha256':records[0]['cfg']['workload_manifest_sha256'],
        'source_runs':[r['path'] for r in records],
        'sources':[{'run':r['path'],'max_tokens':r['cfg']['max_tokens'],'max_model_len':r['cfg']['max_model_len'],
                    'generation_timeout_s':r['cfg']['generation_timeout_s'],
                    'hashes':r['original_hashes'],'submission':r['concurrency'],'verified_source':r['verified_source']}
                   for r in records],
        'model_settings_by_cap':{r['cfg']['max_tokens']:{**r['signature'],'generation_timeout_s':r['cfg']['generation_timeout_s']} for r in records},
        'third_stage_contrast':'24576 changes output cap, context and generation deadline; not a pure output-budget effect',
        'quality_admission':'pending_isolated_audit_labels_and_saturation_review',
        'reviewer_frozen':False,'execution_authorized':False,'main_matrix_authorized':False,
        'inference_calls':0,'candidate_execution':False}
    return json.loads(json.dumps(value,allow_nan=False))


def verified_receipt(path, legacy_source=None):
    value=read_json(path)
    if value.get('schema')!=SCHEMA or value.get('cap_policy')!=POLICY:
        raise ValueError('Use a newly recomputed v2 receipt; legacy fallback is not the new decision')
    rebuilt=report(value['source_runs'],legacy_source)
    if rebuilt!=value:
        raise ValueError('V2 receipt differs from original records')
    return value


def verify_inherited(cfg, value):
    # Reject recursive off-mode references before report validates any config.
    if (value.get('cap_policy')!=POLICY or value.get('stratum_id')!='q38-thinking'
        or value.get('status')!='cap_recommended' or value.get('max_tokens')!=cfg.get('max_tokens')
        or value.get('max_model_len')!=cfg.get('max_model_len')):
        raise ValueError('Thinking-off must inherit the final on-mode CAP AND CONTEXT')
    for p in value.get('source_runs',[]):
        if read_json(Path(p)/'run.json')['config'].get('stratum_id')!='q38-thinking':
            raise ValueError('On-mode originals only; no recursive off-mode receipt')
    return verified_receipt(cfg['inherited_cap_receipt'],cfg.get('cap_legacy_source'))


def verify_prerequisite(cfg):
    path=Path(cfg.get('cap_prerequisite_receipt',''))
    if not path.is_file() or file_sha(path)!=cfg.get('cap_prerequisite_receipt_sha256'):
        raise ValueError('Third stage requires the original hashed v2 prerequisite receipt')
    value=read_json(path)
    if (value.get('schema')!=SCHEMA or value.get('stratum_id')!=cfg['stratum_id']
        or value.get('status')!='needs_larger_cap_pilot' or value.get('next_max_tokens')!=24576
        or value.get('next_max_model_len')!=32768):
        raise ValueError('Third-stage prerequisite not satisfied')
    # Prevent cycles before any config validation: parents must be ONLY the
    # two lower on-mode stages. Never follow a third/off-mode parent recursively.
    parent_caps=[]
    for p in value.get('source_runs',[]):
        parent=read_json(Path(p)/'run.json')['config']
        if (parent.get('stratum_id')!=cfg['stratum_id'] or parent.get('max_model_len')!=16384
            or parent.get('max_tokens') not in (8192,12288)):
            raise ValueError('Prerequisite must reference only the paired two lower stages')
        parent_caps.append(parent['max_tokens'])
    if sorted(parent_caps)!=[8192,12288]:
        raise ValueError('Both lower stages are required exactly once')
    return verified_receipt(path,cfg.get('cap_legacy_source'))


def prepare_proposal(receipt_path, legacy_source=None, *, thinking_off=False):
    """CPU-only configuration draft. All new-stage approvals remain false."""
    from lcb_admission import proposal
    value=verified_receipt(receipt_path,legacy_source)
    name=value['stratum_id']
    if thinking_off:
        if name!='q38-thinking' or value['status']!='cap_recommended':
            raise ValueError('Qwen off mode requires final on-mode v2 recommendation')
        target='q38-nonthinking'; cap=value['max_tokens']
    else:
        if (name not in ('q38-thinking','q35-thinking','nemotron-thinking')
            or value['status']!='needs_larger_cap_pilot' or value['next_max_tokens']!=24576
            or value['next_max_model_len']!=32768
            or [s['max_tokens'] for s in value['sources']]!=[8192,12288]):
            raise ValueError('Third stage requires the original two failed stages under the v2 rule')
        target=name; cap=24576
    cfg=proposal(target,cap)
    prior=read_json(Path(value['source_runs'][-1])/'run.json')['config']
    for key in ('weights_dir','weights_manifest','inference_sif','inference_sif_sha256','seed_appendix'):
        cfg[key]=prior[key]
    cfg.update(cap_prerequisite_receipt=str(Path(receipt_path).resolve(strict=True)),
               cap_prerequisite_receipt_sha256=file_sha(receipt_path),
               cap_legacy_source=str(Path(legacy_source).resolve(strict=True)) if legacy_source else None)
    if thinking_off:
        cfg.update(inherited_cap_receipt=cfg['cap_prerequisite_receipt'],
                   inherited_cap_receipt_sha256=cfg['cap_prerequisite_receipt_sha256'])
    return cfg


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='action',required=True)
    r=sub.add_parser('report');r.add_argument('--runs',nargs='+',required=True)
    d=sub.add_parser('proposal');d.add_argument('--receipt',required=True);d.add_argument('--thinking-off',action='store_true')
    for parser in (r,d):
        parser.add_argument('--legacy-source');parser.add_argument('--output',required=True)
    a=p.parse_args()
    value=(report(a.runs,a.legacy_source) if a.action=='report' else
           prepare_proposal(a.receipt,a.legacy_source,thinking_off=a.thinking_off))
    write_new(a.output,value)
    print(json.dumps({'output':a.output,'execution_authorized':False,'status':value.get('status','proposal_only')}))


if __name__=='__main__':main()
