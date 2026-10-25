"""Reproduce the retail-pricing comparisons from anonymous saved service inputs."""
from fractions import Fraction as F
from itertools import product
from pathlib import Path
import hashlib
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_generalizations import game

ROOT = Path(__file__).resolve().parent
ORDER = ['coder-nonthinking','nemotron-thinking','q35-thinking','q38-nonthinking','q38-thinking']
NAMES = dict(zip(ORDER,['Coder','Nemotron','Qwen3.5 thinking','Qwen3.8 non-thinking','Qwen3.8 thinking']))
Q = (1,8)
HALF = F(1,2)
CENTER = F(12,5)


def need(ok, message):
    if not ok:
        raise ValueError(message)


class Data:
    def __init__(self, evidence=None):
        self.evidence = Path(evidence or ROOT/'evidence')
        read=lambda name:json.loads((self.evidence/name).read_text(),parse_float=str)
        self.input=read('retail-pricing-inputs.json')
        self.reference=read('retail-pricing-reference.json')
        self.provenance=read('service-followup-provenance.json')
        need(self.input['schema']=='retail-pricing-inputs-v1' and self.input['tasks']==106,'Retail input schema')
        self.cells={}
        p={(x['stratum'],x['config'],x['k'],int(x['replicate'][1:])):x for x in self.provenance['service_cells']}
        for row in self.input['cells']:
            key=(row['stratum'],row['config'],row['k'],row['rep'])
            need(key not in self.cells and key in p,'Retail cell identity')
            need(type(row['qplus_count']) is int and type(row['qminus_count']) is int and min(row['qplus_count'],row['qminus_count'])>=0 and row['qplus_count']+row['qminus_count']<=106,'Retail counts')
            need(row['source_extract_sha256']==p[key]['source_extract_sha256'],'Retail source binding')
            self.cells[key]={**row,'qplus':F(row['qplus_count'],106),'qminus':F(row['qminus_count'],106),'tau':F(row['latency_hours']),'tokens':{k:F(v) for k,v in row['tokens_per_request'].items()},'resource':p[key]}
        need(len(self.cells)==len(p)==66,'Retail coverage')
        need(all(c['tau']>=0 and min(c['tokens'].values())>=0 for c in self.cells.values()),'Nonnegative measured quantities')
        need(self.input['energy_assumption']==read('results-manifest.json')['energy_assumption'],'Retail energy scenario consistency')
        for model in ORDER:
            for rep in range(3):
                matched=[self.cells[model,cfg,k,rep]['resource']['gpu_identity_sha256'] for cfg,k in product(('serial','batch16'),Q)]
                need(len(set(matched))==1,'Retail within-repetition hardware pairing')

    def cell(self, model, config, k, rep):
        return self.cells[model,config,k,rep]

    def cost(self,c,rho=CENTER,basis='service',endpoint='mid'):
        e=c['resource'];energy=self.input['energy_assumption']
        span=F(e['generation_span_s_exact'])
        if basis=='service':
            wall=gpu=F(e['service_window_s_exact']);cpu=F(e['service_cpu_usec'],10**6)
        else:
            wall=F(e['lifetime_service_wall_ns'],10**9);gpu=F(e['gpu_step_occupancy_ns'],10**9);cpu=F(e['service_cpu_startup_usec'],10**6)
        def at(i):
            kwh=F(energy['gpu_tdp_w'][e['gpu_model']])*(span*F(energy['busy_fraction_of_tdp'][i])+(wall-span)*F(energy['idle_fraction_of_tdp'][i]))/3600000
            return (rho*gpu/3600+F(self.input['electricity_usd_per_kwh'])*kwh+F(self.input['cpu_usd_per_core_hour'])*cpu/3600)/106
        return (at(0)+at(1))/2 if endpoint=='mid' else at(0 if endpoint=='low' else 1)

    def benchmark(self,model,config,anchor=None,variant='middle_only'):
        anchor=anchor or self.input['headline_anchors'][model]
        rate=self.input['prices'][anchor]
        cells={(k,r):self.cell(model,config,k,r) for k,r in product(Q,range(3))}
        visible={kr:(F(rate['input_per_million'])*c['tokens']['input']+F(rate['output_per_million'])*c['tokens']['delivered'])/10**6 for kr,c in cells.items()}
        base=sum(visible.values())/6
        bill={kr:(base if variant=='middle_only' else visible[kr])+F(rate['output_per_million'])*c['tokens']['hidden_all']/10**6 for kr,c in cells.items()}
        means={k:sum(bill[k,r] for r in range(3))/3 for k in Q}
        return {'cells':cells,'bill':bill,'base':base,'means':means,'P':sum(means.values())/2}

    def arms(self,b,rep,w=HALF):
        p=(1-w)*b['means'][1]+w*b['means'][8]
        return {'A':tuple(b['bill'][k,rep] for k in Q),'D':(p,p)}

    def outcomes(self,b,rep,w=HALF,alpha=HALF,fee=None,rho=CENTER,basis='service',energy=('mid','mid')):
        arms=self.arms(b,rep,w);cost=tuple(self.cost(b['cells'][k,rep],rho,basis,en) for k,en in zip(Q,energy))
        fee=b['P']/2 if fee is None else fee
        result={}
        for upstream,controller,j in product(('S','R'),('M','C'),('A','D')):
            bill=arms[j];transfer=tuple(alpha*x for x in bill) if upstream=='S' else (fee,fee)
            # Positive surplus is a sign condition, not an estimated valuation.
            o=game(bill,transfer,(F(0),F(0)),cost,tuple(x+1 for x in bill),controller)
            result[upstream+controller+j]=sorted(0 if x is None else Q[x] for x in o)
        return result

    @staticmethod
    def purchase(c,bill):
        return {'constant':bill/c['qplus'],'v_coefficient':F(1),'d':c['qminus']/c['qplus'],'h':c['tau']/c['qplus'],'u0':1/c['qplus']}

    def switch(self,cells,rho=CENTER,basis='service'):
        a,b=cells;dq=b['qplus']-a['qplus'];need(dq>0,'Positive correct-delivery increment')
        return {'constant':(self.cost(b,rho,basis)-self.cost(a,rho,basis))/dq,'v_coefficient':F(1),'d':(b['qminus']-a['qminus'])/dq,'h':(b['tau']-a['tau'])/dq,'u0':F(0)}

    def thresholds(self,b,r):
        c=[b['cells'][k,r] for k in Q]
        return {'user':{j:[self.purchase(cc,bb) for cc,bb in zip(c,vals)] for j,vals in self.arms(b,r).items()},'social_zero':[self.purchase(x,self.cost(x)) for x in c],'social_switch':self.switch(c)}

    def robust_intervals(self):
        b=self.benchmark('q38-nonthinking','batch16');lo=[];hi=[];ineq=[];alo=[];ahi=[]
        for r,basis,en in product(range(3),('service','service_startup'),product(('low','high'),repeat=2)):
            c=tuple(self.cost(b['cells'][k,r],CENTER,basis,e) for k,e in zip(Q,en))
            span=b['means'][8]-b['means'][1]
            lo.append((c[0]/HALF-b['means'][1])/span);hi.append((c[1]/HALF-b['means'][1])/span)
            c0=tuple(self.cost(b['cells'][k,r],F(0),basis,e) for k,e in zip(Q,en))
            c1=tuple(self.cost(b['cells'][k,r],F(1),basis,e) for k,e in zip(Q,en))
            slopes=tuple(y-x for x,y in zip(c0,c1));aa=self.arms(b,r)['A']
            ineq.extend([(-slopes[0],HALF*aa[0]-c0[0]),(slopes[1],c0[1]-HALF*aa[1]),(slopes[0],c0[0]-HALF*b['P']),(-slopes[1],HALF*b['P']-c0[1])])
        lower=F(0);upper=None
        for slope,base in ineq:
            if slope<0:lower=max(lower,-base/slope)
            elif slope>0:upper=-base/slope if upper is None else min(upper,-base/slope)
            else:need(base<0,'Empty robust cost interval')
        for r,basis in product(range(3),('service','service_startup')):
            aa=self.arms(b,r)['A'];clo=[self.cost(b['cells'][k,r],CENTER,basis,'low') for k in Q];chi=[self.cost(b['cells'][k,r],CENTER,basis,'high') for k in Q]
            alo.extend([chi[0]/b['P'],chi[1]/aa[1],(chi[1]-clo[0])/(aa[1]-aa[0])]);ahi.append(clo[1]/b['P'])
        return {'D_only_1_joint_reference_weight':[max(F(0),*lo),min(F(1),*hi)],'joint_capacity_for_A8_D1_alpha_half_w_half':[lower,upper],'joint_alpha_for_A8_D1_at_center_w_half':[max(alo),min(F(1),*ahi)]}


def fraction_tree(x):
    if isinstance(x,dict):return {k:fraction_tree(v) for k,v in x.items()}
    if isinstance(x,list):return [fraction_tree(v) for v in x]
    return F(x)


def verify(evidence=None):
    d=Data(evidence);n=0
    for row in d.reference['central']:
        b=d.benchmark(row['st'],row['cfg'],row['anchor'],row['variant']);r=row['rep']
        for field,actual in [('base',b['base']),('mean1',b['means'][1]),('mean8',b['means'][8]),('P50',b['P']),('F0',b['P']/2)]:
            need(actual==F(row[field]),'Reference price match: '+field)
        need({j:list(v) for j,v in d.arms(b,r).items()}==fraction_tree(row['B']),'Reference bills')
        need([d.cost(b['cells'][k,r]) for k in Q]==fraction_tree(row['C']),'Reference resource costs')
        need(d.outcomes(b,r)==row['outcomes_assuming_strict_user_purchase'],'Reference budget outcomes')
        need(d.thresholds(b,r)==fraction_tree(row['thresholds']),'Reference welfare/purchase thresholds')
        n+=1
    for row in d.reference['social_thresholds']:
        cells=[d.cell(row['stratum'],row['config'],k,row['rep']) for k in Q]
        for basis,record in row['threshold_coefficients'].items():
            t0=d.switch(cells,F(0),basis);t1=d.switch(cells,F(1),basis)
            need({**{k:v for k,v in t0.items() if k!='v_coefficient'},'rho':t1['constant']-t0['constant']}==fraction_tree(record),'Five-deployment welfare threshold')
    for row in d.reference['unquoted_price_thresholds']:
        for i,k in enumerate(Q):
            c=d.cell(row['stratum'],row['config'],k,row['rep']);I=c['tokens']['input'];N=c['tokens']['delivered']+c['tokens']['hidden_all'];C=d.cost(c,CENTER,row['basis'])
            need(C==F(row['cost_at_center'][i]) and I==F(row['input_tokens'][i]) and N==F(row['billed_output_tokens'][i]),'Unquoted model inputs')
            old=row['out_price_break_even'][i]
            need(C*10**6/N==F(old['a']) and I/N==F(old['input_price_coefficient']),'Unquoted-model price floor')
    need(d.robust_intervals()==fraction_tree(d.reference['robust_intervals']),'Joint sensitivity intervals')
    indexed={(x['st'],x['cfg'],x['anchor'],x['rep'],x['variant']):x for x in d.reference['central']}
    count=0;differences=[]
    for key,row in indexed.items():
        if key[-1]!='middle_only':continue
        alternative=indexed[key[:-1]+('full_tokens',)]
        count+=key[2]==d.input['headline_anchors'][key[0]]
        if row['outcomes_assuming_strict_user_purchase']!=alternative['outcomes_assuming_strict_user_purchase']:
            differences.append({'key':list(key[:-1]),'middle':row['outcomes_assuming_strict_user_purchase'],'full_tokens':alternative['outcomes_assuming_strict_user_purchase']})
    sensitivity={'main_quote_budget_profiles':count,'mismatches':differences,'main_quote_mismatches':sum(x['key'][2]==d.input['headline_anchors'][x['key'][0]] for x in differences)}
    need(sensitivity==d.reference['full_token_sensitivity'],'Full-token sensitivity counts')
    return {'status':'retail_results_recomputed','service_cells':66,'reference_contract_profiles':n,'social_budget_pairs':len(d.reference['social_thresholds']),'new_experiments':False,'user_values_estimated':False}


def dec(x,n=3):
    return f'{float(x):.{n}f}'


def table(caption,label,columns,header,rows,wide=False):
    kind='table*' if wide else 'table'
    return '\n'.join([f'\\begin{{{kind}}}[t]',r'\caption{'+caption+'}',r'\label{'+label+'}',r'\centering\small',r'\begin{tabular}{'+columns+'}',r'\toprule',header+r' \\',r'\midrule',*[line+r' \\' for line in rows],r'\bottomrule',r'\end{tabular}',f'\\end{{{kind}}}'])+'\n'


def display_o(o):
    return r'\varnothing' if o==[0] else str(o[0]) if len(o)==1 else r'\{'+','.join(str(k) for k in o)+r'\}'


def render():
    d=Data();files={}
    short={'coder-nonthinking':'Coder','nemotron-thinking':'Nemotron','q35-thinking':'Qwen3.5','q38-nonthinking':'Qwen3.8 off','q38-thinking':'Qwen3.8 on'}
    rows=[]
    for model in ORDER:
        for k in Q:
            cells=[d.cell(model,'batch16',k,r) for r in range(3)]
            plus=dec(sum(c['qplus'] for c in cells)/3*100,1)
            minus=dec(sum(c['qminus'] for c in cells)/3*100,1)
            costs=[d.cost(c)*1000 for c in cells]
            rows.append((short[model] if k==1 else '')+f' & {k} & {plus} & {minus} & '+dec(min(costs),2)+'--'+dec(max(costs),2))
    files['retail-profiles.tex']=table(r'Batch16 service profiles.','tab:retail-profiles','@{}lcrrr@{}',r'Deployment & $k$ & $q^+$ (\%) & $q^-$ (\%) & \shortstack{Cost\\(USD/1k)}',rows)
    rows=[]
    for model in ORDER[2:]:
        b=d.benchmark(model,'batch16')
        for r in range(3):
            o=d.outcomes(b,r)
            vals=['$'+display_o(o[key])+'$' for key in ['SMA','SMD','SCA','SCD']]
            rows.append((short[model] if r==0 else '')+f' & $r_{r}$ & '+' & '.join(vals))
    files['retail-decisions.tex']=table(r'Budget choices under revenue sharing.','tab:retail-decisions','@{}llcccc@{}',r'Deployment & Repeat & $A_M$ & $D_M$ & $A_C$ & $D_C$',rows)
    b=d.benchmark('q38-nonthinking','batch16');rows=[]
    for arm in ['A','D']:
        for i,k in enumerate(Q):
            bill=d.arms(b,0)[arm][i];cost=d.cost(b['cells'][k,0])
            rows.append(('Metered' if arm=='A' else 'Fixed')+f' & {k} & '+' & '.join(dec(x*1000,2) for x in [bill,cost,bill/2,bill/2-cost]))
    files['retail-payoffs.tex']=table(r'Payoffs conditional on execution.','tab:retail-payoffs','@{}lrrrrr@{}',r'Pricing & $k$ & Bill & Cost & $\Pi_M$ & $\Pi_C$',rows)
    rows=[]
    for model in ORDER:
        for r in range(3):
            t=d.switch([d.cell(model,'batch16',k,r) for k in Q])
            rows.append((short[model] if r==0 else '')+f' & $r_{r}$ & '+' & '.join(dec(t[key],4) for key in ('constant','d','h')))
    files['retail-thresholds.tex']=table(r'Welfare-threshold coefficients by deployment.','tab:retail-thresholds','@{}llrrr@{}',r'Deployment & Repeat & $a$ & $b$ & $c$',rows)
    intervals=d.robust_intervals();keys=list(intervals);rows=[]
    names=[r'Reference weight $w$',r'Capacity cost $\rho$',r'Cloud share $\alpha$']
    settings=[r'$\rho=2.4,\ \alpha=0.5$',r'$w=0.5,\ \alpha=0.5$',r'$w=0.5,\ \rho=2.4$']
    for name,key,setting in zip(names,keys,settings):
        lo,hi=intervals[key];rows.append(name+' & '+dec(lo,2)+'--'+dec(hi,2)+' & '+setting)
    files['retail-sensitivity.tex']=table(r'Ranges preserving the budget difference.','tab:retail-sensitivity','@{}lcl@{}',r'Parameter & Range & Fixed parameters',rows)
    rows=[]
    for model in ORDER[:2]:
        for r in range(3):
            vals=[]
            for k in Q:
                c=d.cell(model,'batch16',k,r);N=c['tokens']['delivered']+c['tokens']['hidden_all']
                vals.extend([dec(d.cost(c)*10**6/N,4),dec(c['tokens']['input']/N,4)])
            rows.append((short[model] if r==0 else '')+f' & $r_{r}$ & '+' & '.join(vals))
    files['retail-unquoted.tex']=table(r'Price floors for Coder and Nemotron.','tab:retail-unquoted','@{}llrrrr@{}',r'Deployment & Repeat & $a_1$ & $b_1$ & $a_8$ & $b_8$',rows)
    return files


def numbers():
    d=Data();b=d.benchmark('q38-nonthinking','batch16');t=d.thresholds(b,0)
    names={'constant':'Const','d':'Error','h':'Wait','u0':'Outside'};out={}
    for prefix,obj in [('rtThreshold',t['social_switch']),('rtBuyMetered',t['user']['A'][1]),('rtBuyFixed',t['user']['D'][0])]:
        for key,suffix in names.items():out[prefix+suffix]=dec(obj[key],4)
    out['rtAdditionalCorrect']=str(b['cells'][8,0]['qplus_count']-b['cells'][1,0]['qplus_count'])
    out['rtAdditionalWrong']=str(b['cells'][8,0]['qminus_count']-b['cells'][1,0]['qminus_count'])
    out['rtMainProfiles']=str(d.reference['full_token_sensitivity']['main_quote_budget_profiles'])
    out['rtPromoDifferences']=str(len(d.reference['full_token_sensitivity']['mismatches']))
    for model,tag in [('coder-nonthinking','Coder'),('nemotron-thinking','Nemotron')]:
        slopes=[d.switch([d.cell(model,'batch16',k,rep) for k in Q])['d'] for rep in range(3)]
        out['rt'+tag+'ErrorLow']=f'{float(min(slopes)):g}'
        out['rt'+tag+'ErrorHigh']=f'{float(max(slopes)):g}'
    return out


def phase_tex():
    d=Data();b=d.benchmark('q38-nonthinking','batch16');B=d.arms(b,0)['A'];P=b['P']
    text=(ROOT/'figures/src/pricing-phase-template.tex').read_text()
    for suffix,rho in [('0',F('1.9')),('1',F('3.4'))]:
        costs=[d.cost(b['cells'][k,0],rho) for k in Q]
        for key,value in [('A',costs[1]/B[1]),('L',costs[0]/P),('H',costs[1]/P)]:
            text=text.replace('@'+key+suffix+'@',dec(value,10))
    need('@' not in text,'Unresolved phase coordinate')
    return text


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
    if '--write-phase' in sys.argv:
        (ROOT/'figures/src/pricing-phase.tex').write_text(phase_tex())
