#!/bin/bash
#
# Runs inside the SHARED environment image (environment/Dockerfile) — canonical TB2 has no
# separate verifier image. pytest is baked into environment/Dockerfile, so do NOT install or
# download anything here — verify-time setup is rejected by the static checks.
#
# Put your pytest files (e.g. test_outputs.py) in tests/ and run them below. Harbor overlays
# tests/ at /tests only at verify time, so keep ground truth / expected outputs in tests/
# (never in environment/, where the agent could read them).
# --ctrf writes a standard JSON report; write 1/0 to /logs/verifier/reward.txt.
pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA

if [ $? -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
