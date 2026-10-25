"""Token-ID partitioning and code extraction, never executable model output."""
import re


def find_sequence(tokens,marker,start=0):
    if not marker:raise ValueError('Empty reasoning delimiter')
    for i in range(start,len(tokens)-len(marker)+1):
        if tokens[i:i+len(marker)]==marker:return i
    return None


def partition_tokens(tokens,mode,opening=None,closing=None,prefix_open=False):
    if any(type(x) is not int or x<0 for x in tokens):raise ValueError('Raw token ids required')
    if mode=='none':
        return {'reasoning_ids':[],'control_ids':[],'final_ids':list(tokens),'status':'nonthinking'}
    if mode!='think_tags':raise ValueError('Unknown reasoning protocol')
    opening,closing=list(opening or []),list(closing or [])
    if not opening or not closing:raise ValueError('Tokenizer delimiter ids required')
    start=0;control=[]
    if not prefix_open:
        if tokens[:len(opening)]!=opening:raise ValueError('Expected initial thinking marker, not a mid-answer tag')
        start=len(opening);control=tokens[:start]
    stop=find_sequence(tokens,closing,start)
    if stop is None:
        result={'reasoning_ids':tokens[start:],'control_ids':control,'final_ids':[],
                'status':'unclosed_reasoning_no_final'}
    else:
        result={'reasoning_ids':tokens[start:stop],
                'control_ids':control+tokens[stop:stop+len(closing)],
                'final_ids':tokens[stop+len(closing):],'status':'closed_reasoning'}
    assert sum(len(result[k]) for k in ('reasoning_ids','control_ids','final_ids'))==len(tokens)
    return result


def extract_code(final_text):
    """Unique Python-tagged block (ignoring non-Python examples), or bare code.

Multiple Python blocks are ambiguous and never concatenated. Syntax/semantics
are left to the isolated judge; this function only extracts text.
"""
    matches=re.findall(r'```([^\n`]*)\n(.*?)```',final_text,re.DOTALL)
    if final_text.count('```')!=2*len(matches):return {'code':None,'extraction':'unclosed_fence'}
    if matches:
        python=[text for language,text in matches if language.strip().lower() in ('python','python3','py')]
        if len(python)!=1:return {'code':None,'extraction':'ambiguous_or_nonpython_fences'}
        if not python[0].strip():return {'code':None,'extraction':'empty_final'}
        return {'code':python[0].strip()+'\n','extraction':'single_python_fence'}
    if '```' in final_text:return {'code':None,'extraction':'unclosed_fence'}
    if not final_text.strip():return {'code':None,'extraction':'empty_final'}
    return {'code':final_text.strip()+'\n','extraction':'bare'}


def episode_meters(candidates,selected_id):
    if len({c['candidate_id'] for c in candidates})!=len(candidates):raise ValueError('Duplicate candidate id')
    if selected_id is not None and selected_id not in {c['candidate_id'] for c in candidates}:
        raise ValueError('Unknown delivered candidate')
    if selected_id is not None:
        selected=next(c for c in candidates if c['candidate_id']==selected_id)
        if selected.get('truncated') is True or selected.get('finish_reason')=='length':
            raise ValueError('Truncated candidate cannot be delivered; retain its generated tokens')
    missing=[{'candidate_id':c['candidate_id'],'reason':c.get('metering_error') or 'missing_token_partition'}
             for c in candidates if c.get('token_partition') is None]
    if missing:
        return {'metering_status':'incomplete','reasoning_tokens_all':None,
                'unselected_final_tokens':None,'delivered_output_tokens':None,
                'missing_candidates':missing}
    reasoning=unselected=delivered=total=0
    for c in candidates:
        part=c['token_partition'];r=len(part['reasoning_ids'])+len(part['control_ids']);f=len(part['final_ids'])
        reasoning+=r;total+=r+f
        if c['candidate_id']==selected_id:delivered+=f
        else:unselected+=f
    assert total==reasoning+unselected+delivered
    return {'metering_status':'complete','generated_tokens_total':total,'reasoning_tokens_all':reasoning,
            'unselected_final_tokens':unselected,'delivered_output_tokens':delivered,
            'control_tokens_in_reasoning_meter':True,'synthetic_refusal_tokens':0}


def deferred_meters(candidates):
    """No selection means unknown delivery, NOT an observed refusal."""
    value=episode_meters(candidates,None)
    value['final_tokens_all']=value['unselected_final_tokens']
    value.update(unselected_final_tokens=None,delivered_output_tokens=None,
                 selection_status='deferred',synthetic_refusal_tokens=None)
    return value
