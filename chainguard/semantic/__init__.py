"""Semantic (content-level) checks run BEFORE attestation.

These checks are separate from cryptographic verification on purpose:

* cryptographic integrity answers "is this exactly what was signed?" with
  near-certainty;
* semantic checks answer "does the content look benign?" with heuristics that have
  false positives and false negatives, and that an adaptive attacker can evade.

A semantic flag therefore yields WARNING, never FAILED, and its results are recorded
(and signed) inside the manifest so later stages know which checks were run.
"""
