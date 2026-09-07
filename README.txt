SysRepair: Autonomous Remediation of Running Systems
ACSAC 2026 -- Artifact Submission
====================================================

WHAT THIS ARTIFACT IS

SysRepair is a benchmark and evaluation harness for autonomous vulnerability
remediation on LIVE systems, as opposed to source-code repair. Each scenario is
a containerised host running a vulnerable service. A solver acts only through a
bash tool, and success is a hard conjunction: the canonical exploit must no
longer succeed AND every previously-operational service must still answer on its
declared port.

The artifact contains the scenario corpus, the execution harness, all six solver
implementations including the NeuroPlan neural-symbolic planner, and the
evaluation logs underlying the numbers in the paper.

CONTENTS

  artifact/          scenario corpus, harness, solvers, analysis scripts
  infrastructure/    platform requirements, access notes, resource envelope
  claims/            one directory per evaluated paper claim
  install.sh         one-click dependency setup
  README.txt         this file
  license.txt        license name and URL
  use.txt            intended use and limitations

QUICK START

  ./install.sh                      # dependencies, images, python env
  cd claims/claim1 && ./run.sh      # smallest claim, ~20 minutes

Each claims/claimN/ holds claim.txt (the paper statement under test), run.sh
(reproduces it), and expected/ (the reference output to compare against).

SCALE, AND WHY EVERY CLAIM SHIPS A SCALED-DOWN MODE

The full evaluation grid in the paper is six solvers against three models over
313 scenarios in two information conditions at five epochs. That is on the order
of tens of thousands of container-backed episodes and several thousand GPU-hours;
it is not reproducible inside an evaluation window, and we do not ask reviewers
to attempt it.

Every run.sh therefore defaults to a SCALED subset that exercises the identical
code path and completes in the time stated in its claim.txt. Passing SCALE=full
runs the paper-scale configuration for anyone with the budget. The complete
evaluation logs behind the published numbers ship in artifact/logs/, so every
published cell can be recomputed exactly without re-running any model.

WHAT REQUIRES CREDENTIALS

The hosted-model solvers need an API key for the corresponding provider. The
open-weight models (Qwen3.5-9B, Qwen3.5-35B-A3B) are served locally with vLLM
and need a CUDA GPU. Claims that require neither are marked NO-CREDENTIALS in
their claim.txt and can be reproduced from the shipped logs alone.
