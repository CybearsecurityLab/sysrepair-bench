"""Write every regenerated exhibit into the paper, one table at a time, each
replacement scoped between its \\label and \\bottomrule with a row-count check."""
import json, re, statistics as st
S = "/tmp/claude-1000/-home-resbears-projects-sysrepair-bench/2b197629-f832-46be-b9e0-d22418033f6b/scratchpad/"
P = "/home/resbears/projects/iclr-2027/sections/"
T = json.load(open(S + "tables_v3.json")); R8 = json.load(open(S + "round8.json"))
C = json.load(open(S + "cost_rule.json")); X = json.load(open(S + "excl_episodes.json"))
MODELS = [("deepseek-v4-flash", "DeepSeek-V4-Flash"), ("minimax-m3", "MiniMax-M3"), ("minimax-m2.7", "MiniMax-M2.7"),
          ("qwen3.5-4b", "Qwen3.5-4B"), ("qwen3.5-9b", "Qwen3.5-9B"), ("qwen3.5-27b", "Qwen3.5-27B"),
          ("qwen3.5-35b", "Qwen3.5-35B"), ("qwen3.5-122b", "Qwen3.5-122B")]
SUITES = ["meta2", "vulnhub", "ccdc", "meta3-ub", "sr-modern"]
f1 = lambda x: "\\result" if x is None else f"{x:.1f}"
def body(path, label, rows, expect):
    s = open(path).read(); a = s.index("\\label{" + label + "}"); m = s.index("\\midrule", a); b = s.index("\\bottomrule", m)
    old = [l for l in s[m + 8:b].strip("\n").split("\n") if l.strip()]
    assert len(old) == expect == len(rows), (label, len(old), expect, len(rows))
    s = s[:m + 8] + "\n" + "\n".join(rows) + "\n" + s[b:]; open(path, "w").write(s)
def sub(path, old, new):
    s = open(path).read(); assert s.count(old) == 1, (path, old[:60]); open(path, "w").write(s.replace(old, new))

# Table 1
rows = []
for mk, mn in MODELS:
    g = T["grid"][mn]
    rows.append(f"{mn:<17}& " + " & ".join(f"{f1(g[s][0])}/{f1(g[s][1])}" for s in SUITES) + " \\\\")
body(P + "06_results.tex", "tab:results-full", rows, 8)

# tab:main
best = {c: max(T["main"][f"{mn}|{c}"]["@5"] for _, mn in MODELS) for c in ("report", "discovery-required")}
rows = []
for c in ("report", "discovery-required"):
    for mk, mn in MODELS:
        v = T["main"][f"{mn}|{c}"]; i = 0 if c == "report" else 1
        per = [T["grid"][mn][s][i] for s in SUITES]
        macro = "\\result" if None in per else f"{st.mean(per):.1f}"
        p5 = f"{v['@5']:.1f}"; p5 = f"\\textbf{{{p5}}}" if v["@5"] == best[c] else p5
        rows.append(f"{mn} & {c} & {v['S']} & " + " & ".join(f"{v[f'@{k}']:.1f}" for k in range(1, 5)) +
                    f" & {p5} & {macro} & $[{v['ci'][0]:.1f},\\,{v['ci'][1]:.1f}]$ \\\\")
body(P + "10_appendix.tex", "tab:main", rows, 16)

# tab:ladder + fig:ladder
rows = []; cd, cr, pr = [], [], []
for mk, mn in MODELS[3:]:
    a = T["cdr"][f"{mn}|day1"]; b = T["cdr"][f"{mn}|zero_day"]
    ra = T["main"][f"{mn}|report"]["@5"]; rb = T["main"][f"{mn}|discovery-required"]["@5"]
    rows.append(f"{mn:<13}& {ra:.1f} & {a['cdr']:.1f}\\% & {a['n_s']} & {rb:.1f} & {b['cdr']:.1f}\\% & {b['n_s']} \\\\")
    r = mn.split("-")[1]; cd.append(f"({r},{b['cdr']:.1f})"); cr.append(f"({r},{a['cdr']:.1f})"); pr.append(f"({r},{ra:.1f})")
body(P + "10_appendix.tex", "tab:ladder", rows, 5)
s = open(P + "10_appendix.tex").read()
s = re.sub(r"(\\addplot\[mark=triangle\*,thick,black,dotted\] coordinates \{)[^}]*\}", lambda m: m.group(1) + "".join(cd) + "}", s)
s = re.sub(r"(\\addplot\[mark=\*,thick,black\] coordinates \{)[^}]*\}", lambda m: m.group(1) + "".join(cr) + "}", s)
s = re.sub(r"(\\addplot\[mark=square,thick,dashed,gray\] coordinates \{)[^}]*\}", lambda m: m.group(1) + "".join(pr) + "}", s)
open(P + "10_appendix.tex", "w").write(s)

# fig:cdr
lab = ["DS-Flash", "M3", "M2.7", "4B", "9B", "27B", "35B", "122B"]
def coords(cond):
    return "{" + " ".join(f"({l},{T['cdr'][f'{mn}|{cond}']['cdr']:.1f})" for l, (_, mn) in zip(lab, MODELS)) + "}"
s = open(P + "06_results.tex").read()
a = s.index("\\addplot+[fill=gray!35] coordinates"); b = s.index(";", a)
s = s[:a] + "\\addplot+[fill=gray!35] coordinates\n  " + coords("day1") + s[b:]
a = s.index("\\addplot+[fill=black!70] coordinates"); b = s.index(";", a)
s = s[:a] + "\\addplot+[fill=black!70] coordinates\n  " + coords("zero_day") + s[b:]
open(P + "06_results.tex", "w").write(s)

# tab:paired-gap
rows = []
for mk, mn in MODELS:
    v = T["paired"][mn]
    rows.append(f"{mn:<17} & {v['n']} & {v['RI']:.1f} & {v['DR']:.1f} & {v['gap']:.1f} & $[{v['ci'][0]:.1f},\\,{v['ci'][1]:.1f}]$ & $<0.0004$ \\\\")
    assert v["nonpos"] == 0
body(P + "10_appendix.tex", "tab:paired-gap", rows, 8)

# tab:cdr-condition
rows = []
for mk, mn in MODELS:
    a = T["cdr"][f"{mn}|day1"]; b = T["cdr"][f"{mn}|zero_day"]
    rows.append(f"{mn:<17} & {a['E_c']} & {a['n_s']} & {a['cdr']:.1f}\\% & $[{a['ci'][0]:.1f},\\,{a['ci'][1]:.1f}]$ & "
                f"{b['E_c']} & {b['n_s']} & {b['cdr']:.1f}\\% & $[{b['ci'][0]:.1f},\\,{b['ci'][1]:.1f}]$ \\\\")
body(P + "10_appendix.tex", "tab:cdr-condition", rows, 8)

# tab:taxonomy
rows = []
for mk, mn in MODELS:
    for cond, lab2 in (("day1", "RI"), ("zero_day", "DR")):
        v = T["cdr"][f"{mn}|{cond}"]; n = v["failed"]
        coll_only = v["coll"]
        assert coll_only + v["notrem"] + v["both"] == n, (mn, cond)
        rows.append(f"{mn} & {lab2} & {n} & {100*coll_only/n:.1f} & {100*v['notrem']/n:.1f} & {100*v['both']/n:.1f} \\\\")
body(P + "10_appendix.tex", "tab:taxonomy", rows, 16)

# tab:cost
rows = []
for mk, mn in MODELS:
    a = C[f"{mk}|day1"]; b = C[f"{mk}|zero_day"]
    fp = lambda x, e: (f"${x:.2f}\\pm{e:.2f}$" if x < 10 else f"${x:.1f}\\pm{e:.1f}$")
    rows.append(f"{mn} & ${a['ktok']:.0f}\\pm{a['ktok_se']:.0f}$ & {fp(a['pflop'], a['pflop_se'])} & ${a['s']:.0f}\\pm{a['s_se']:.0f}$ & "
                f"${b['ktok']:.0f}\\pm{b['ktok_se']:.0f}$ & {fp(b['pflop'], b['pflop_se'])} & ${b['s']:.0f}\\pm{b['s_se']:.0f}$ \\\\")
body(P + "10_appendix.tex", "tab:cost", rows, 8)

# tab:contam
rows = []
for mk, mn in MODELS:
    a = T["contam"].get(f"{mn}|day1"); b = T["contam"].get(f"{mn}|zero_day")
    cell = lambda v: (f"{v['pre']:.1f} & {v['post']:.1f}" if v else "\\result & \\result")
    rows.append(f"{mn} & {cell(a)} & {cell(b)} \\\\")
body(P + "10_appendix.tex", "tab:contam", rows, 8)

# tab:episodes
rows = []
for mk, mn in MODELS:
    for cond, lab2 in (("day1", "RI"), ("zero_day", "DR")):
        v = R8[f"{mn}|{cond}"]; x = X.get(f"{mk}|{cond}", {})
        rows.append(f"{mn} & {lab2} & {v['S']} & {v['kept']} & {x.get('no_verdict', 0)} & {x.get('unusable', 0)} & {x.get('short', 0)} & {v['budget']} \\\\")
s = open(P + "10_appendix.tex").read()
s = s.replace("\\begin{tabular}{llrrrrr}\n\\toprule\nModel & Cond. & $S$ & kept & no verdict & unusable & budget \\\\",
              "\\begin{tabular}{llrrrrrr}\n\\toprule\nModel & Cond. & $S$ & kept & no verdict & unusable & short ctx & budget \\\\")
open(P + "10_appendix.tex", "w").write(s)
body(P + "10_appendix.tex", "tab:episodes", rows, 16)
print("applied")
