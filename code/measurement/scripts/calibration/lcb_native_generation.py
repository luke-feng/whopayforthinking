"""Explicit vendor-native generation contract, CPU-audited at frozen revisions.

This parameters-only package DOES NOT release the new cap chain or owner
launcher. Constants live in this module because only /worker is container-bound.
"""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re

POLICY='vendor-native-generation-v1'
CAP_POLICY='vendor-native-cap-v3'
SOURCE_AUDIT_SHA='371bcd3035145b3c703c12f7faa8711e19b901828c7b752b1d809c49390cebe0'
SAMPLING=('temperature','top_p','top_k','min_p','presence_penalty','repetition_penalty','frequency_penalty')
FIELDS=('generation_policy','native_contract_sha256','native_source_audit_sha256','stratum_id',
        'native_preset','reasoning_effort','chat_template_kwargs','native_template_sha256',
        'native_metadata_sha256','eos_policy',*SAMPLING)
PRESETS={
 'q38-thinking':{'model_id':'Qwen/Qwen3.8-27B','model_revision':'1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0',
  'reasoning_mode':'think_tags','native_preset':'vendor-thinking','sampling':[1.0,.95,20,0.0,0.0,1.0,0.0],
  'template':'c3cf9e34abf4f9e36c2d72165aa9c132d3e2a725b6c2586aaa3a8af9d7a81041',
  'tokenizer_config':'b11349aafa7cdc6a320767cf7ceb29ed82f7eda5d65e8e0819e76f0ce947bf27',
  'generation_config':'e70c136c1b78ddc1fb0905bac8e733a4dc448d4f852a5dd75143fffc70be550e'},
 'q35-thinking':{'model_id':'Qwen/Qwen3.5-9B','model_revision':'c202236235762e1c871ad0ccb60c8ee5ba337b9a',
  'reasoning_mode':'think_tags','native_preset':'vendor-thinking-general','sampling':[1.0,.95,20,0.0,1.5,1.0,0.0],
  'template':'a4aee8afcf2e0711942cf848899be66016f8d14a889ff9ede07bca099c28f715',
  'tokenizer_config':'316230d6a809701f4db5ea8f8fc862bc3a6f3229c937c174e674ff3ca0a64ac8','generation_config':None},
 'nemotron-thinking':{'model_id':'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16','model_revision':'bf77c3174f68ad409e1c2aa60daeb46e32d1c606',
  'reasoning_mode':'think_tags','native_preset':'vendor-reasoning-neutral-unspecified','sampling':[1.0,1.0,0,0.0,0.0,1.0,0.0],
  'template':'ab7813c3abdd9cb655905a410728b26c7884eca45ddfab8d9f931553485a7862',
  'tokenizer_config':'3d568e506d0905285ae90a3fdd1482be7b6d0bf0b8ca9514d75dad4257b0827a',
  'generation_config':'7a8f2d91a749d7a09b755daceacab14da9d66ebfdaea7e8583e48c0be01ee73d'},
 'coder-nonthinking':{'model_id':'Qwen/Qwen2.5-Coder-7B-Instruct','model_revision':'c03e6d358207e414f1eca0bb1891e29f1db0e242',
  'reasoning_mode':'none','native_preset':'vendor-generation-config','sampling':[.7,.8,20,0.0,0.0,1.1,0.0],
  'template':'cd8e9439f0570856fd70470bf8889ebd8b5d1107207f67a5efb46e342330527f',
  'tokenizer_config':'959e7f1d9a1b7641a6d6ce05ca97b75c7894fcb66cbe5a040406458fb1128ee4',
  'generation_config':'1a628a5775bc69cde01c6749a531150ca4d3189652c618a174f7077923acf3b1'},
}
PRESETS['q38-nonthinking']={**PRESETS['q38-thinking'],'reasoning_mode':'none',
    'native_preset':'vendor-nonthinking','sampling':[.7,.8,20,0.0,1.5,1.0,0.0]}


def sha(raw):return hashlib.sha256(raw).hexdigest()


def canonical(value):return sha(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())


CONTRACT_SHA=canonical(PRESETS)


def active(cfg):return cfg.get('generation_policy')==POLICY


def settings(name,effort=None):
    if name not in PRESETS:raise ValueError('Unknown native model stratum')
    p=PRESETS[name]
    if name=='q38-thinking':
        if effort not in ('medium','low'):raise ValueError('New Qwen thinking uses explicit medium or low, never implicit xhigh')
        kwargs={'enable_thinking':True,'reasoning_effort':effort,'preserve_thinking':True}
    else:
        if effort is not None:raise ValueError('No native effort level for this stratum')
        kwargs=({'enable_thinking':False,'preserve_thinking':True} if name=='q38-nonthinking' else
                {} if name=='coder-nonthinking' else {'enable_thinking':True})
    metadata={'tokenizer_config.json':p['tokenizer_config'],'generation_config.json':p['generation_config'],
              'chat_template.jinja':None if name=='coder-nonthinking' else p['template']}
    return {'generation_policy':POLICY,'native_contract_sha256':CONTRACT_SHA,'native_source_audit_sha256':SOURCE_AUDIT_SHA,
        'stratum_id':name,'model_id':p['model_id'],'model_revision':p['model_revision'],'reasoning_mode':p['reasoning_mode'],
        'native_preset':p['native_preset'],'reasoning_effort':effort,'chat_template_kwargs':kwargs,
        'native_template_sha256':p['template'],'native_metadata_sha256':metadata,
        'eos_policy':'model-native-eos-no-forced-thinking-close',**dict(zip(SAMPLING,p['sampling']))}


def validate(cfg):
    expected=settings(cfg.get('stratum_id'),cfg.get('reasoning_effort'))
    for key,value in expected.items():
        if key not in cfg or cfg[key]!=value:raise ValueError('Native generation field differs: '+key)
    for key in SAMPLING:
        value=cfg[key]
        if type(value) not in (int,float) or not math.isfinite(value) or (key=='top_k' and type(value) is not int):
            raise ValueError('Explicit finite sampling parameter required: '+key)
    # Python equality conflates True and 1; template controls must not do so.
    if canonical(cfg['chat_template_kwargs'])!=canonical(expected['chat_template_kwargs']):
        raise ValueError('Native template argument types differ')
    for key in ('reasoning_budget','thinking_token_budget','stop','stop_token_ids','ignore_eos',
                'repetition_detection','logit_bias','allowed_token_ids'):
        if key in cfg:raise ValueError('Unreviewed generation override: '+key)


def profile_settings(cfg):
    validate(cfg)
    return deepcopy({k:cfg[k] for k in FIELDS})


def require_current_execution(cfg):
    if active(cfg):
        validate(cfg)
        if cfg.get('execution_purpose')=='model_admission_pilot' and cfg.get('cap_chain_protocol')=='native-admission-chain-v3':
            from lcb_admission_v3 import verify_for_execution
            verify_for_execution(cfg)
            return
        raise ValueError('Native execution is not released: only verified v3 admission pilots are allowed')
    if cfg.get('execution_purpose') in ('model_admission_pilot','scientific_collection'):
        raise ValueError('Superseded generation protocol: historical replay only; no new collection')


def sampling_kwargs(cfg,seed):
    validate(cfg)
    if type(seed) is not int:raise ValueError('Explicit candidate seed required')
    return {**{k:cfg[k] for k in SAMPLING},'n':1,'seed':seed,'max_tokens':cfg['max_tokens'],
            'min_tokens':0,'ignore_eos':False,'stop':[],'stop_token_ids':[],
            'thinking_token_budget':None}


def submitted_parameters(parameters,cfg,seed):
    wanted=sampling_kwargs(cfg,seed)
    observed={key:deepcopy(getattr(parameters,key)) for key in wanted}
    if canonical(observed)!=canonical(wanted):raise ValueError('SamplingParams differs from explicit native request')
    return observed


def verify_model_metadata(root,cfg):
    validate(cfg);result={}
    for name,expected in cfg['native_metadata_sha256'].items():
        p=Path(root)/name
        if expected is None:
            if p.exists() or p.is_symlink():raise ValueError('Unexpected metadata file at frozen revision: '+name)
            result[name]=None
        else:
            if not p.is_file() or sha(p.read_bytes())!=expected:raise ValueError('Native metadata bytes changed: '+name)
            result[name]=expected
    return result


def metadata_evidence(root,tokenizer,cfg):
    result=verify_model_metadata(root,cfg)
    template=tokenizer.get_chat_template()
    if not isinstance(template,str) or sha(template.encode())!=cfg['native_template_sha256']:
        raise ValueError('Actually selected native template differs')
    return {'generation_policy':POLICY,'native_template_sha256':sha(template.encode()),
            'native_metadata_sha256':result,'chat_template_kwargs':deepcopy(cfg['chat_template_kwargs']),
            'sampling_parameters_scope':'explicit submitted object before engine EOS augmentation',
            'tokenizer_eos_token_id':tokenizer.eos_token_id}


def validate_backend_evidence(evidence,cfg):
    if (not isinstance(evidence,dict) or evidence.get('generation_policy')!=POLICY
        or evidence.get('native_template_sha256')!=cfg['native_template_sha256']
        or evidence.get('native_metadata_sha256')!=cfg['native_metadata_sha256']
        or canonical(evidence.get('chat_template_kwargs'))!=canonical(cfg['chat_template_kwargs'])
        or evidence.get('sampling_parameters_scope')!='explicit submitted object before engine EOS augmentation'
        or type(evidence.get('tokenizer_eos_token_id')) is not int):
        raise ValueError('Backend native configuration evidence differs')


def render_evidence(tokenizer,cfg,prompt):
    validate(cfg)
    messages=[{'role':'system','content':cfg['system_prompt']},{'role':'user','content':prompt}]
    text=tokenizer.apply_chat_template(messages,tokenize=False,add_generation_prompt=True,**cfg['chat_template_kwargs'])
    if not isinstance(text,str) or not text:raise ValueError('Actual rendered prompt text required')
    ids=tokenizer.encode(text,add_special_tokens=False)
    if not isinstance(ids,list) or not ids or any(type(x) is not int or x<0 for x in ids):raise ValueError('Actual input IDs required')
    suffix=('<|im_start|>assistant' if cfg['stratum_id']=='coder-nonthinking' else
            '<think>' if cfg['reasoning_mode']=='think_tags' else '</think>')
    if not text.rstrip().endswith(suffix):raise ValueError('Native prompt suffix differs')
    if cfg['stratum_id']=='q38-thinking':
        system=text.split('<|im_end|>',1)[0]
        if cfg['reasoning_effort']=='medium' and 'Reasoning effort is set to ' in system:
            raise ValueError('Medium unexpectedly contains low/xhigh instruction')
        if cfg['reasoning_effort']=='low' and 'Reasoning effort is set to low.' not in system:
            raise ValueError('Low control not applied by native template')
    evidence={'input_tokens':len(ids),'input_ids_sha256':canonical_ids(ids),
        'rendered_prompt_sha256':sha(text.encode()),'rendered_prompt_bytes':len(text.encode()),
        'native_template_sha256':cfg['native_template_sha256'],
        'chat_template_kwargs_sha256':canonical(cfg['chat_template_kwargs'])}
    return ids,evidence


def canonical_ids(ids):return sha(json.dumps(ids,separators=(',',':')).encode())


def validate_prompt_evidence(evidence,cfg):
    for key in ('input_ids_sha256','rendered_prompt_sha256'):
        if not re.fullmatch('[0-9a-f]{64}',str(evidence.get(key,''))):raise ValueError('Missing actual prompt digest: '+key)
    if type(evidence.get('rendered_prompt_bytes')) is not int or evidence['rendered_prompt_bytes']<=0:
        raise ValueError('Positive rendered prompt byte length required')
    if (evidence.get('native_template_sha256')!=cfg['native_template_sha256'] or
        evidence.get('chat_template_kwargs_sha256')!=canonical(cfg['chat_template_kwargs'])):
        raise ValueError('Prompt template/mode provenance differs')


def validate_sample(row,cfg):
    validate_prompt_evidence(row,cfg)
    if type(row.get('input_tokens')) is not int or row['input_tokens']!=len(row['input_token_ids']):
        raise ValueError('Actual input-token count required')
    if row['input_ids_sha256']!=canonical_ids(row['input_token_ids']):raise ValueError('Input IDs differ from rendered evidence')
    if (row.get('generation_policy')!=POLICY or
        canonical(row.get('sampling_parameters_submitted'))!=canonical(sampling_kwargs(cfg,row['seed']))):
        raise ValueError('Sample missing actual explicit sampling parameters')


def match_prompt_evidence(row,preflight):
    for key in ('input_tokens','input_ids_sha256','rendered_prompt_sha256','rendered_prompt_bytes',
                'native_template_sha256','chat_template_kwargs_sha256'):
        if key not in row or key not in preflight or type(row[key]) is not type(preflight[key]) or row[key]!=preflight[key]:
            raise ValueError('Candidate prompt differs from whole-roster preflight: '+key)
