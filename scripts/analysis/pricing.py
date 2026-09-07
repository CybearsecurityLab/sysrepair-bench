"""Model pricing, as a DATED SNAPSHOT.

Deliberately hard-coded rather than fetched. Provider prices change, and a cost
table that silently re-prices itself against a live tariff would stop
reproducing the paper the moment a vendor updated a rate card. These are the
figures quoted in the paper's Experimental Setup section.

USD per million tokens.
"""
SNAPSHOT_DATE = "2026-08-20"

PRICES = {
    "minimax-m2.7": {"input": 0.60, "output": 2.40, "cached_input": 0.06},
}


def cost_usd(model: str, n_in: int, n_out: int, n_total: int) -> float:
    """Dollars for one episode.

    Cached tokens are ESTIMATED as total - input - output, because the provider
    does not report them separately. The paper states this; it is reproduced
    rather than corrected so the artifact matches the publication. Absolute
    dollars are sensitive to the assumption; the solver-to-solver RATIOS the
    claim rests on are not.
    """
    p = PRICES.get(model.lower())
    if p is None:
        raise KeyError(f"no pricing snapshot for {model!r}; add it to pricing.py")
    cached = max(0, n_total - n_in - n_out)
    return (n_in * p["input"] + n_out * p["output"] + cached * p["cached_input"]) / 1e6
