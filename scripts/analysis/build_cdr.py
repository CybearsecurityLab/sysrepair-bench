"""CDR, scaffold CDR and failure taxonomy from the SAME episode cache as pass@k.

Components come from the scorer's structured summary where present, else from
recovered.json (the pre-verifylib verifier's labelled checks, validated against
its exit code). An episode enters the CDR pool E_c only when both components are
known. The taxonomy is computed over exactly E_c, so its failed count equals
E_c - joint and its collateral count equals n_s * CDR, row for row.
"""
import json, os, sys
from collections import defaultdict

S = os.path.dirname(os.path.abspath(__file__))
rec = json.load(open(os.path.join(S, "recovered_none.json")))  # structured verdicts only: no old-format recoveries
M = [("deepseek-v4-flash", "DeepSeek-V4-Flash"), ("minimax-m3", "MiniMax-M3"),
     ("minimax-m2.7", "MiniMax-M2.7"), ("qwen3.5-4b", "Qwen3.5-4B"),
     ("qwen3.5-9b", "Qwen3.5-9B"), ("qwen3.5-27b", "Qwen3.5-27B"),
     ("qwen3.5-35b", "Qwen3.5-35B"), ("qwen3.5-122b", "Qwen3.5-122B")]

eps = {}
for line in open(os.path.join(S, "eps_raw.jsonl")):
    base, model, scaf, mode, sid, ep, outs, sec, reg, bm = json.loads(line)
    if sec is None:
        r = rec.get(f"{base}|{sid}|{ep}")
        if r: sec, reg = r
    k = (model, scaf, mode, sid, ep)
    if k not in eps or base > eps[k][0]:
        eps[k] = (base, outs, sec, reg)


def cell(model, scaf, mode):
    E = [v for k, v in eps.items() if k[0] == model and k[1] == scaf and k[2] == mode]
    pool = [v for v in E if v[2] is not None and v[3] is not None]
    ns = sum(1 for v in pool if v[2]); joint = sum(1 for v in pool if v[2] and v[3])
    coll = sum(1 for v in pool if v[2] and not v[3])
    notrem = sum(1 for v in pool if (not v[2]) and v[3])
    both = sum(1 for v in pool if (not v[2]) and (not v[3]))
    return dict(episodes=len(E), E_c=len(pool), n_s=ns, joint=joint,
                cdr=None if not ns else 100 * coll / ns,
                failed=len(pool) - joint, coll=coll, notrem=notrem, both=both)


out = {"cdr": {}, "scaffold": {}}
for mk, mn in M:
    for mode in ("day1", "zero_day"):
        out["cdr"][f"{mn}|{mode}"] = cell(mk, "react", mode)
for mk, mn in M:
    for scaf in ("basic", "react", "reflexion", "plan_and_solve"):
        c = cell(mk, scaf, "day1")
        if c["n_s"] >= 30: out["scaffold"][f"{mn}|{scaf}"] = c
json.dump(out, open(os.path.join(S, "cdr_tables.json"), "w"), indent=1)

print(f"{'model':<18}{'mode':<9}{'eps':>6}{'E_c':>6}{'cover':>7}{'n_s':>6}{'CDR':>7}{'failed':>8}{'coll%':>7}{'notrem%':>8}{'both%':>7}")
for k, c in out["cdr"].items():
    m, mo = k.split("|"); f = max(1, c["failed"])
    print(f"{m:<18}{mo:<9}{c['episodes']:>6}{c['E_c']:>6}{100*c['E_c']/max(1,c['episodes']):>6.0f}%{c['n_s']:>6}{c['cdr']:>6.1f}%"
          f"{c['failed']:>8}{100*c['coll']/f:>7.1f}{100*c['notrem']/f:>8.1f}{100*c['both']/f:>7.1f}")
print("\nscaffold (report-informed):")
for k, c in out["scaffold"].items():
    print(f"  {k:<32} n_s={c['n_s']:5d} CDR={c['cdr']:5.1f}%  (E_c {c['E_c']} of {c['episodes']})")
