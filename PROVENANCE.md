# Scenario corpus: composition, provenance, and licensing

## Composition

313 scenarios across seven suites, matching Table `tab:inventory` in the paper.

| Suite | Count | Target | Notes |
|---|---:|---|---|
| `ccdc` | 50 | Ubuntu/Debian containers | also the NeuroPlan evaluation subset |
| `meta2` | 40 | Ubuntu 8.04 containers | oldest userland; 7 compensating-control scenarios |
| `vulnhub` | 30 | mixed Linux containers | derived from public VulnHub images |
| `meta3/ubuntu` | 19 | Ubuntu containers | |
| `meta3/windows` | 21 | Windows Server containers | needs a Docker engine in Windows-container mode |
| `meta4` | 137 | mixed | 117 at `meta4/scenario-*` plus 20 at `meta4/ad-vm/scenario-*` |
| `hivestorm` | 16 | mixed | continuous scoring, zero-day only |
| **Total** | **313** | | |

### Two counting traps, both of which have bitten us

**meta4 is 137, not 117.** Twenty scenarios live at `meta4/ad-vm/scenario-*`,
one directory level below `meta4/scenario-*`. A glob of `meta4/scenario-*`
returns 117 and a naive suite total comes to 293. The harness has the same blind
spot: a benchmark spec of `meta4` discovers 117, so a run config must name
`meta4/ad-vm` explicitly or every meta4 cell silently evaluates 117 of 137 while
claiming the full suite.

**Scenario ids are not unique across suites.** `ccdc/scenario-01` and
`vulnhub/scenario-01` are different scenarios. Any analysis keying on the last
path segment silently merges them; we measured a 37% undercount in a mixed-suite
cell from exactly this. Key on the full sample id.

### Excluded from the corpus

`meta3/windows-vm/` held VM-standalone variants (`"mode": "vm-standalone"`) of
three scenarios that already exist as containers under `meta3/windows/`:
`scenario-10-smbv1`, `scenario-11-smb-signing`, `scenario-12-rdp-nla`. They are
an alternative execution mode for the same vulnerabilities, were not part of the
published evaluation, and are omitted so the shipped corpus is exactly the 313
the paper reports.

## Provenance and licensing

Scenarios are original constructions, but several are modelled on public
material and the vulnerable software they install carries its own upstream
license.

- **`vulnhub`** — modelled on publicly published VulnHub practice images. The
  scenario definitions here are ours; the vulnerable services are stock upstream
  packages under their own licenses.
- **`ccdc`** — modelled on publicly documented Collegiate Cyber Defense
  Competition practice material.
- **`hivestorm`** — modelled on publicly documented Hivestorm practice material,
  including its incremental scoring convention.
- **`meta2`, `meta3`, `meta4`** — original, built on stock distribution images
  (Ubuntu 8.04 and later, Debian, Windows Server) with real CVE-bearing or
  misconfigured service versions.

Every scenario ships a `threat.md` recording the vulnerability, its severity and
CVE where one exists, and a `verify.sh` (or `verify-poc.ps1` / `verify-service.ps1`
on Windows) implementing the oracle.

## Dual use

Each scenario contains a working check that the vulnerability is exploitable,
used to verify that remediation succeeded. These target only the disposable
container supplied with the scenario. See `use.txt` at the artifact root for the
reasoning behind shipping them.
