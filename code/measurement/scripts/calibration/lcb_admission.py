"""Frozen per-model admission settings. Proposals are not execution approval."""
import argparse
import json
from pathlib import Path
import re
from lcb_cap_policy import POLICY as CAP_POLICY, envelope, generation_timeout
import lcb_native_generation as native

ROOT=Path(__file__).resolve().parents[2]
PANEL=ROOT/'data/calibration/model-panel-theory-aligned-v2.json'
PURPOSE='model_admission_pilot'
REVIEW_REFERENCE=('review/model-admission-pilot-v1-review.md; '
                 'pre-dispatch guard 1e149e54b14d827d56231edb5163336301668198; '
                 'owner-relayed supervisor approval 2026-10-10')


def validate_tokenization(tokenized,cfg,task_ids):
    """Whole frozen roster must fit BEFORE any candidate is dispatched."""
    if (tokenized.get('event')!='tokenized_prompts' or tokenized.get('generation_executed') is not False
        or not task_ids or len(task_ids)!=len(set(task_ids))):
        raise ValueError('Complete native tokenization preflight required')
    rows=tokenized.get('rows')
    if not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows) or [r.get('task_id') for r in rows]!=task_ids:
        raise ValueError('Tokenization must cover the entire frozen roster in order')
    too_long=[]
    if native.active(cfg):
        native.validate(cfg)
        if native.canonical(tokenized.get('generation_settings'))!=native.canonical(native.profile_settings(cfg)):
            raise ValueError('Tokenization native generation settings differ')
    for row in rows:
        n=row.get('input_tokens')
        if type(n) is not int or n<1 or not re.fullmatch('[0-9a-f]{64}',str(row.get('input_ids_sha256',''))):
            raise ValueError('Actual positive token length and token-ID digest required')
        if n+cfg['max_tokens']>cfg['max_model_len']:too_long.append(row['task_id'])
        if native.active(cfg):native.validate_prompt_evidence(row,cfg)
    if too_long:
        raise ValueError('Frozen workload prompt plus output cap exceeds context before generation; return to review: '+', '.join(too_long))


def stratum(name):
    rows=json.loads(PANEL.read_text())['strata']
    found=[r for r in rows if r['stratum_id']==name]
    if len(found)!=1:raise ValueError('Unknown frozen model stratum')
    return found[0]


def validate(cfg):
    explicit=native.active(cfg)
    if explicit:native.validate(cfg)
    s=stratum(cfg.get('stratum_id'))
    if (cfg.get('execution_purpose')!=PURPOSE or cfg.get('subset')!='pilot' or cfg.get('judge')!='deferred'
        or cfg.get('k')!=8 or cfg.get('pool_id')!=1 or cfg.get('concurrency')!=16
        or cfg.get('sampling_seed_policy')!='sha256-prefix63-v1'
        or type(cfg.get('replicate_id')) is not int or cfg['replicate_id'] not in (0,1,2)):
        raise ValueError('Admission is frozen 16-task k8 batch16 generation, not a main/online launch')
    if (cfg['model_id']!=s['model_id'] or cfg['model_revision']!=s['revision']
        or cfg['reasoning_mode']!=s['reasoning_mode']):raise ValueError('Admission model or native mode changed')
    context=envelope(s['stratum_id'],cfg.get('max_tokens'))
    if explicit and s['stratum_id']!='coder-nonthinking' and cfg['max_tokens'] not in (12288,24576):
        raise ValueError('New native admission begins at 12288, not the old 8192 stage')
    memory_fraction=.85 if s['stratum_id']=='coder-nonthinking' else .90
    if (cfg.get('max_model_len')!=context or cfg.get('generation_timeout_s')!=generation_timeout(cfg['max_tokens'])
        or cfg.get('max_num_seqs')!=64 or cfg.get('cache_mode')!='off'
        or (not explicit and (cfg.get('temperature')!=.8 or cfg.get('top_p')!=.95)) or cfg.get('seed')!=20261006
        or cfg.get('gpu_memory_utilization')!=memory_fraction or cfg.get('arrival_offsets_s')!=[0]*16
        or cfg.get('expected_vllm_version')!='0.30.0' or cfg.get('expected_gpu_name')!='NVIDIA H100 80GB HBM3'):
        raise ValueError('Admission settings differ from proposed fixed envelope')
    if cfg.get('inference_text_only') is not s['model_id'].startswith(('Qwen/Qwen3.8','Qwen/Qwen3.5')):
        raise ValueError('Frozen text-only architecture setting required')
    for key in ('reviewer_approved','owner_approved'):
        if cfg.get(key) is not False:raise ValueError('Admission must not authorize online execution')
    review=cfg.get('admission_review',{})
    if (review.get('reviewer_approved') is not True or review.get('owner_approved') is not True
        or not review.get('review_reference') or str(review['review_reference']).startswith('OWNER_')):
        raise ValueError('Admission package requires independent reviewer and owner approval')
    if explicit:
        mode_review=cfg.get('native_mode_review',{})
        if (mode_review.get('reviewer_approved') is not True or mode_review.get('owner_approved') is not True
            or not mode_review.get('review_reference') or str(mode_review['review_reference']).startswith('OWNER_')):
            raise ValueError('New native mode package needs separate review and owner approval')
        if cfg.get('cap_policy')!=native.CAP_POLICY:raise ValueError('Native cap-v3 marker required')
        if context==32768:
            extended=cfg.get('extended_admission_review',{})
            if (extended.get('reviewer_approved') is not True or extended.get('owner_approved') is not True
                or not extended.get('review_reference') or str(extended['review_reference']).startswith('OWNER_')):
                raise ValueError('24576 still needs independent extended-envelope approval')
        if cfg.get('cap_chain_protocol') is not None:
            from lcb_admission_v3 import validate_shape
            validate_shape(cfg)  # Pure shape; receipt traversal belongs to v3.
        # The collector's release gate remains closed pending fresh review.
        return
    if context==32768:
        extended=cfg.get('extended_admission_review',{})
        if (cfg.get('cap_policy')!=CAP_POLICY or extended.get('reviewer_approved') is not True
            or extended.get('owner_approved') is not True or not extended.get('review_reference')
            or str(extended['review_reference']).startswith('OWNER_')):
            raise ValueError('Extended cap/context pair requires a separately reviewed implementation and owner approval')
        if s['stratum_id']!='q38-nonthinking':
            from lcb_admission_v2 import verify_prerequisite
            verify_prerequisite(cfg)
    if s['stratum_id']=='q38-nonthinking':
        # A source-bound on-mode cap receipt is checked by the read-only planner;
        # the collector must not accept an arbitrary inherited number.
        from lcb_admission_report import verify_inherited_cap
        verify_inherited_cap(cfg)


def proposal(name,cap):
    s=stratum(name)
    cfg=json.loads((ROOT/'experiments/calibration/lcb-lifecycle-acceptance.template.json').read_text())
    context=envelope(name,cap)
    cfg.update(stratum_id=name,execution_purpose=PURPOSE,k=8,pool_id=1,concurrency=16,
        model_id=s['model_id'],model_revision=s['revision'],reasoning_mode=s['reasoning_mode'],max_tokens=cap,max_model_len=context,
        gpu_memory_utilization=.85 if name=='coder-nonthinking' else .90,
        inference_text_only=s['model_id'].startswith(('Qwen/Qwen3.8','Qwen/Qwen3.5')),
        inherited_cap_receipt='OWNER_Q38_ON_CAP_RECEIPT' if name=='q38-nonthinking' else None,
        inherited_cap_receipt_sha256='MISSING' if name=='q38-nonthinking' else None,
        compile_cache_dir='/data/site/www27-compile-cache-'+name,
        note='Generation-only admission pilot and whole-roster pre-dispatch guard reviewed. Actual assets and owner approval remain required. Native model mode; no judging or main collection.')
    for field in ('deferred_review','lifecycle_review','admission_review'):
        cfg[field]={'reviewer_approved':True,'owner_approved':False,'review_reference':REVIEW_REFERENCE}
    if context==32768:
        cfg['cap_policy']=CAP_POLICY
        cfg['generation_timeout_s']=generation_timeout(cap)
        cfg['extended_admission_review']={'reviewer_approved':False,'owner_approved':False,
                                         'review_reference':'OWNER_REVIEW_EXTENDED_CAP_IMPLEMENTATION'}
        cfg['note']='Third-stage proposal only; original two-stage permission does not approve this implementation.'
    return cfg


def native_proposal(name,cap,effort=None):
    if name=='q38-thinking' and effort is None:effort='medium'
    if name!='coder-nonthinking' and cap not in (12288,24576):
        raise ValueError('New native drafts use 12288/16k or 24576/32k only')
    cfg=proposal(name,cap)
    cfg.update(native.settings(name,effort))
    cfg.update(cap_policy=native.CAP_POLICY,
        note='Parameters-only native draft; cap-v3 state machine and new owner wrapper are not released. Historical approvals do not apply.')
    for key in ('deferred_review','lifecycle_review','admission_review','native_mode_review'):
        cfg[key]={'reviewer_approved':False,'owner_approved':False,'review_reference':'OWNER_NEW_NATIVE_PACKAGE_REVIEW'}
    if cap==24576:
        cfg['extended_admission_review']={'reviewer_approved':False,'owner_approved':False,
            'review_reference':'OWNER_NEW_EXTENDED_ENVELOPE_REVIEW'}
    cfg['compile_cache_dir']='/data/site/www27-native-cache-'+name+'-'+(effort or 'default')
    return cfg


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stratum',required=True);parser.add_argument('--max-tokens',required=True,type=int)
    parser.add_argument('--native',action='store_true',help='New parameter draft only; execution remains closed')
    parser.add_argument('--reasoning-effort',choices=('medium','low'))
    args=parser.parse_args()
    if args.reasoning_effort and not args.native:parser.error('--reasoning-effort requires --native')
    print(json.dumps(native_proposal(args.stratum,args.max_tokens,args.reasoning_effort) if args.native else
                     proposal(args.stratum,args.max_tokens),indent=2))


if __name__=='__main__':main()
