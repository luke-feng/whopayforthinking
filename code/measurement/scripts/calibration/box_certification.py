"""Exact vertices of the approved multi-affine P2 margin box.

This is conditional algebra, not a fitted empirical confidence set. Ratios,
geometric kernels and arbitrary user expressions are deliberately unsupported.
"""
from fractions import Fraction as F
from itertools import product
from math import isqrt
from thinking_market import number


KEYS = ('alpha','B_L','B_H','V_L','V_H','C0_L','C0_H','C1_L','C1_H','L','u0')


def margins(x, channel):
    a,bl,bh = x['alpha'],x['B_L'],x['B_H']
    c0l,c0h,c1l,c1h = (x[k] for k in ('C0_L','C0_H','C1_L','C1_H'))
    dl,dh = c0h-c0l,c1h-c1l
    welfare_drop = dh-(c0l-c1l)-(x['V_H']-x['V_L'])
    strict = {'alpha_positive':a, 'alpha_below_one':1-a, 'base_bill_positive':bl,
              'bill_increment':bh-bl, 'welfare_drop':welfare_drop}
    weak = {'pool_saving_L':c0l-c1l,'pool_saving_H':c0h-c1h,
            **{k:x[k] for k in ('C0_L','C0_H','C1_L','C1_H','L','u0')}}
    for k in ('L','H'):
        b=x['B_'+k]
        strict['user_'+k]=x['V_'+k]-b-x['u0']
        strict['model_share_'+k]=(1-a)*b
    if channel=='marginal':
        strict.update(delta_cost_positive=dh,cloud_before_low=dl-a*(bh-bl),cloud_after_high=a*(bh-bl)-dh)
        for pi,k in product((0,1),('L','H')):
            c=x[f'C{pi}_{k}'];b=x['B_'+k]
            strict[f'cloud_share_{pi}_{k}']=a*b-c
            strict[f'cloud_rent_{pi}_{k}']=x['L']-c
            strict['model_rent_'+k]=b-x['L']
    elif channel=='admission':
        strict.update(cloud_before_low=a*bl-c0l,cloud_before_high_refusal=c0h-a*bh,
                      cloud_after_high=a*bh-c1h)
    else:
        raise ValueError('Unknown P2 channel')
    return strict,weak


def validate_constraints(constraints):
    for c in constraints:
        if c.get('relation') not in ('eq','le') or not c.get('coefficients'):
            raise ValueError('Only explicit linear consistency constraints supported')
        if set(c['coefficients'])-set(KEYS):
            raise ValueError('Unknown constraint coordinate')
        number(c['rhs'])
        for v in c['coefficients'].values():number(v)


def certify(box,channel,*,constraints=None,feasibility_witness=None,max_vertices=65536):
    if set(box)!=set(KEYS):
        raise ValueError('Only the declared independent multi-affine coordinates are supported')
    bounds={}
    for key,pair in box.items():
        if not isinstance(pair,(tuple,list)) or len(pair)!=2:
            raise ValueError('Each coordinate needs lower and upper bounds')
        lo,hi=map(number,pair)
        if lo>hi:raise ValueError('Empty box')
        bounds[key]=(lo,hi)
    constraints=constraints or []
    validate_constraints(constraints)
    if constraints:
        if feasibility_witness is None or set(feasibility_witness)!=set(KEYS):
            raise ValueError('Constrained set needs a checked feasibility witness')
        w={k:number(v) for k,v in feasibility_witness.items()}
        if any(not bounds[k][0]<=w[k]<=bounds[k][1] for k in KEYS):
            raise ValueError('Witness is outside box')
        for c in constraints:
            lhs=sum((number(v)*w[k] for k,v in c['coefficients'].items()),F(0))
            if (c['relation']=='eq' and lhs!=number(c['rhs'])) or (c['relation']=='le' and lhs>number(c['rhs'])):
                raise ValueError('Witness violates a consistency constraint')
    vertices=[tuple(dict.fromkeys(bounds[k])) for k in KEYS]
    count=1
    for v in vertices:count*=len(v)
    if count>max_vertices:raise ValueError('Vertex budget exceeded; no approximate fallback')
    lows={};weak_lows={};argmins={}
    for values in product(*vertices):
        x=dict(zip(KEYS,values));strict,weak=margins(x,channel)
        for k,v in strict.items():
            if k not in lows or v<lows[k]:lows[k]=v;argmins[k]=x
        for k,v in weak.items():weak_lows[k]=min(weak_lows.get(k,v),v)
    passed=all(v>0 for v in lows.values()) and all(v>=0 for v in weak_lows.values())
    return {'status':'certified' if passed else 'not_certified', 'channel':channel,
            'scope':'conservative_box_relaxation' if constraints else 'exact_multi_affine_box',
            'interpretation':'conditional_algebra_not_empirical_evidence','vertices':count,
            'strict_lower_bounds':{k:str(v) for k,v in lows.items()},
            'weak_lower_bounds':{k:str(v) for k,v in weak_lows.items()},
            'box_argmins':{k:{j:str(v) for j,v in x.items()} for k,x in argmins.items()}}


def rational_hoeffding_band(samples,support,dimensions,delta,denominator=10**6):
    """Conservative rational radius; caller must justify independent blocks.

Take integer m with 2**m >= 2J/delta. Since exp(m) >= 2**m,
radius >= range*sqrt(m/(2N)) implies the simultaneous Hoeffding bound.
The square root is rounded upward on an exact rational grid, without floats.
This conservative radius is wider than the log-based optimal Hoeffding radius.
"""
    if not samples or type(dimensions) is not int or dimensions<1:
        raise ValueError('Nonempty independent blocks and positive dimension required')
    if type(denominator) is not int or denominator<1:
        raise ValueError('Positive rational grid denominator required')
    d=number(delta);lo,hi=map(number,support)
    if not 0<d<1 or lo>hi:raise ValueError('Invalid support or failure probability')
    values=list(map(number,samples))
    if any(not lo<=v<=hi for v in values):raise ValueError('Out-of-support sample')
    target=2*dimensions/d;m=0;power=1
    while power<target:power*=2;m+=1
    squared=F(m,2*len(values))*denominator**2
    root=isqrt(squared.numerator//squared.denominator)
    if F(root*root)<squared:root+=1
    radius=(hi-lo)*F(root,denominator)
    mean=sum(values,F(0))/len(values)
    return {'lower':max(lo,mean-radius),'upper':min(hi,mean+radius),
            'radius':radius,'exponent_lower_bound':F(m)}
