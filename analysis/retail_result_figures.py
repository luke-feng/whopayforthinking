"""Generate the approved vector views of existing retail-result tables."""
from pathlib import Path
from fractions import Fraction as F
import json
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import retail_result_tables as r


def render():
    """Return deterministic TeX and exact plotted values without writing files."""
    files={}
    d=r.Data();short={'coder-nonthinking':'Coder','nemotron-thinking':'Nemotron','q35-thinking':'Qwen3.5','q38-nonthinking':'Qwen3.8 off','q38-thinking':'Qwen3.8 on'}
    ff=lambda x:f'{float(x):.9f}'
    pre=r'''\documentclass[tikz,border=3pt]{standalone}
    \usepackage[tt=false,type1=true]{libertine}
    \usepackage[libertine]{newtxmath}
    \usepackage{pgfplots}
    \usepgfplotslibrary{groupplots}
    \pgfplotsset{compat=1.18}
    \definecolor{accent}{HTML}{466E8B}
    \definecolor{graybar}{HTML}{A1A1A1}
    \begin{document}
    \begin{tikzpicture}
    '''
    post='\\end{tikzpicture}\n\\end{document}\n'
    pre_color=pre.replace(r'\begin{document}',r'\definecolor{metered}{HTML}{0072B2}'+'\n'+r'\definecolor{fixed}{HTML}{D55E00}'+'\n'+r'\definecolor{repzero}{HTML}{0072B2}'+'\n'+r'\definecolor{repone}{HTML}{D55E00}'+'\n'+r'\definecolor{reptwo}{HTML}{009E73}'+'\n'+r'\begin{document}')
    records={'delivery':[],'profits':[],'coefficients':[]}
    # A. Delivery composition: every segment is a mutually exclusive observed outcome.
    text=pre+r'''\begin{axis}[
     width=5.55cm,height=3.8cm,scale only axis,
     xmin=0,xmax=100,ymin=.5,ymax=5.5,
     xtick={0,50,100},ytick={5,4,3,2,1},
     yticklabels={Coder,Nemotron,Qwen3.5,Qwen3.8 off,Qwen3.8 on},
     tick label style={font=\fontsize{7.5}{8.5}\selectfont},
     yticklabel style={xshift=-8pt},
     label style={font=\fontsize{7.5}{8.5}\selectfont},
     xlabel={Share of requests (\%)},
     axis x line*=bottom,axis y line*=left,
     y axis line style={draw=none},ytick style={draw=none},
     tick align=outside,xtick style={black,line width=.45pt},
     axis line style={black,line width=.5pt},clip=false,
     legend columns=3,
     legend style={at={(.5,1.03)},anchor=south,font=\fontsize{7.2}{8.2}\selectfont,draw=none,column sep=3pt},
     legend image code/.code={\draw[##1] (0cm,-.07cm) rectangle (.16cm,.07cm);}
    ]
    \addlegendimage{draw=black!50,fill=accent}\addlegendentry{Correct}
    \addlegendimage{draw=black!50,fill=graybar}\addlegendentry{Incorrect}
    \addlegendimage{draw=black!50,fill=white}\addlegendentry{Abstain}
    '''.replace('##1','#1')
    for i,model in enumerate(r.ORDER):
        center=5-i
        for k,offset in [(1,F(1,5)),(8,-F(1,5))]:
            cells=[d.cell(model,'batch16',k,rep) for rep in range(3)]
            qp=sum(x['qplus'] for x in cells)/3*100
            qm=sum(x['qminus'] for x in cells)/3*100
            qa=100-qp-qm
            assert min(qp,qm,qa)>=0 and qp+qm+qa==100
            y=F(center)+offset
            segments=[(F(0),qp,'accent'),(qp,qp+qm,'graybar'),(qp+qm,F(100),'white')]
            for lo,hi,color in segments:
                text+=f'\\path[fill={color},draw=black!45,line width=.25pt] (axis cs:{ff(lo)},{ff(y-F(1,10))}) rectangle (axis cs:{ff(hi)},{ff(y+F(1,10))});\n'
            text+=f'\\node[anchor=east,font=\\fontsize{{7}}{{8}}\\selectfont] at (axis cs:-3,{ff(y)}) {{{k}}};\n'
            records['delivery'].append({'model':model,'k':k,'correct_pct':str(qp),'incorrect_pct':str(qm),'abstain_pct':str(qa)})
    text+=r'\node[anchor=east,font=\fontsize{7}{8}\selectfont] at (axis cs:-3,5.56) {$k$};'+'\n'+r'\end{axis}'+'\n'+post
    files['delivery-composition.tex']=text

    # B. Compare pricing rules directly within each stakeholder/budget row.
    text=pre_color+r'''\begin{axis}[
     width=5.55cm,height=3.55cm,scale only axis,
     xmin=-15,xmax=55,ymin=.5,ymax=4.5,
     xtick={-10,0,20,40},ytick={4,3,2,1},
     yticklabels={Model firm $k=1$,Cloud $k=1$,Model firm $k=8$,Cloud $k=8$},
     tick label style={font=\fontsize{7.5}{8.5}\selectfont},
     label style={font=\fontsize{7.5}{8.5}\selectfont},
     xlabel={Profit (USD/1,000 requests)},
     axis x line*=bottom,axis y line*=left,
     y axis line style={draw=none},ytick style={draw=none},
     tick align=outside,xtick style={black,line width=.45pt},
     axis line style={black,line width=.5pt},clip=false,
     legend columns=2,
     legend style={at={(.5,1.03)},anchor=south,font=\fontsize{7.2}{8.2}\selectfont,draw=none,column sep=8pt},
     legend image code/.code={\draw[##1] (0cm,-.07cm) rectangle (.16cm,.07cm);}
    ]
    \addlegendimage{draw=metered,fill=metered}\addlegendentry{Metered}
    \addlegendimage{draw=fixed,fill=fixed}\addlegendentry{Fixed}
    '''.replace('##1','#1')
    b=d.benchmark('q38-nonthinking','batch16');arms=d.arms(b,0);profits={}
    for arm,k in [('A',1),('A',8),('D',1),('D',8)]:
        bill=arms[arm][r.Q.index(k)];cost=d.cost(b['cells'][k,0])
        model=bill/2*1000;cloud=(bill/2-cost)*1000
        assert model+cloud==(bill-cost)*1000
        profits[arm,k]=(model,cloud)
        records['profits'].append({'arm':arm,'k':k,'model_profit_per1000':str(model),'cloud_profit_per1000':str(cloud),'conditional_on_execution':True})
    text+=r'\draw[black!20,line width=.35pt] (axis cs:-15,2.5)--(axis cs:55,2.5);'+'\n'
    for index,(who,k) in enumerate([(0,1),(1,1),(0,8),(1,8)]):
        center=4-index
        for arm,offset,color in [('A',F(4,25),'metered'),('D',-F(4,25),'fixed')]:
            value=profits[arm,k][who];y=F(center)+offset
            text+=f'\\path[fill={color},draw={color},line width=.25pt] (axis cs:0,{ff(y-F(11,100))}) rectangle (axis cs:{ff(value)},{ff(y+F(11,100))});\n'
    text+=r'\draw[black,line width=.65pt] (axis cs:0,.5)--(axis cs:0,4.5);'+'\n'+r'\end{axis}'+'\n'+post
    files['supplier-profits.tex']=text

    # C. Coefficients, not selected arbitrary valuations: each marker is one repetition.
    text=pre_color+r'''\begin{groupplot}[
     group style={group size=3 by 1,horizontal sep=10pt},
     width=1.85cm,height=3.8cm,scale only axis,
     ymin=.5,ymax=5.5,ytick={5,4,3,2,1},
     tick label style={font=\fontsize{7.2}{8.2}\selectfont},
     label style={font=\fontsize{7.5}{8.5}\selectfont},
     title style={font=\fontsize{7.8}{8.8}\selectfont},
     tick align=outside,tick style={black,line width=.4pt},
     axis line style={black,line width=.5pt},axis lines*=left,
     scaled ticks=false]
    '''
    styles=[('constant','Cost',r'$a$ (USD)','0.4','{0,.2,.4}'),('d','Errors',r'$b$','2','{0,1,2}'),('h','Waiting',r'$c$ (hours)','10','{0,5,10}')]
    marks=['*','triangle*','square*'];colors=['repzero','repone','reptwo'];offsets=[F(3,20),F(0),-F(3,20)]
    for j,(key,title,xlabel,xmax,ticks) in enumerate(styles):
        labels='yticklabels={Coder,Nemotron,Qwen3.5,Qwen3.8 off,Qwen3.8 on}' if j==0 else 'yticklabels={}'
        text+=f'\\nextgroupplot[xmin=0,xmax={xmax},xtick={ticks},xlabel={{{xlabel}}},title={{{title}}},{labels}]\n'
        for rep in range(3):
            coords=[]
            for i,model in enumerate(r.ORDER):
                t=d.switch([d.cell(model,'batch16',k,rep) for k in r.Q])
                coords.append(f'({ff(t[key])},{ff(F(5-i)+offsets[rep])})')
                if j==0:records['coefficients'].append({'model':model,'rep':rep,'a':str(t['constant']),'b':str(t['d']),'c':str(t['h'])})
            text+=f'\\addplot[only marks,mark={marks[rep]},mark size=1.3pt,{colors[rep]},line width=.35pt] coordinates {{'+''.join(coords)+'};\n'
    text+=r'''\end{groupplot}
    \begin{scope}[shift={([xshift=-19pt,yshift=-8pt]group c3r1.north east)},x=1pt,y=1pt]
     \path[draw=black!60,fill=white,line width=.4pt] (-4.5,5.5) rectangle (16.5,-25.5);
     \draw[only marks,mark=*,mark size=1.3pt,repzero] plot coordinates {(0,0)};
     \node[anchor=west,font=\fontsize{7.2}{8.2}\selectfont] at (4,0) {$r_0$};
     \draw[only marks,mark=triangle*,mark size=1.3pt,repone] plot coordinates {(0,-10)};
     \node[anchor=west,font=\fontsize{7.2}{8.2}\selectfont] at (4,-10) {$r_1$};
     \draw[only marks,mark=square*,mark size=1.3pt,reptwo] plot coordinates {(0,-20)};
     \node[anchor=west,font=\fontsize{7.2}{8.2}\selectfont] at (4,-20) {$r_2$};
    \end{scope}
    '''+post
    files['threshold-coefficients.tex']=text
    records['scope']={'configuration':'batch16','tasks':106,'cost_scenario':'rho=2.4, energy midpoint, service cost basis','delivery':'descriptive means of three repetitions','profits':'Qwen3.8 non-thinking r0, alpha=1/2, matched reference fixed price, zero firm own cost, conditional on executing each proposed budget','thresholds':'v*=a+b*d+c*h, separate repeated measurements, not confidence intervals','new_experiments':False}
    return files,records


if __name__=='__main__':
    r.verify()
    files,records=render()
    for name,text in files.items():
        (ROOT/'figures/src'/name).write_text(text)
    out=ROOT/'output/pdf'
    out.mkdir(parents=True,exist_ok=True)
    (out/'retail-figure-data.json').write_text(json.dumps(records,indent=2)+'\n')
    print(json.dumps({'generated':list(files),'new_estimates':False}))
