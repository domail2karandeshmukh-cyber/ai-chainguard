# Conference proposal

## Provisional titles

1. **"Signed Is Not Safe: Measuring the Boundary Between Cryptographic Integrity and Semantic Trust in AI Supply Chains"** (preferred)
2. "AI-ChainGuard: Hash-Linked, Role-Bound Attestation from Dataset to Deployment"
3. "Verifying the Whole Chain: End-to-End Provenance for Datasets, Fine-Tuned Models and Deployments"

## Research theme

Security of machine-learning systems — AI supply-chain integrity, provenance and attestation; intersection of software supply-chain security (SLSA, in-toto, Sigstore) and adversarial ML (data poisoning, backdoors).

## Abstract direction (≈ 200 words, to finalise in week 8)

AI models are assembled from datasets, pretrained models and fine-tuning steps supplied by different parties, yet software supply-chain controls do not capture this lineage. We present AI-ChainGuard, a prototype that attests each artifact with an Ed25519-signed manifest whose payload embeds the manifest digests of its parents, producing a hash-linked provenance graph from data collection to deployment. A verifier enforces ten checks — content hashes, row-level dataset Merkle roots, signatures, role-bound signer policy, parent links, recursive ancestry, revocation and stage policy — and a deployment gateway loads models only from verified bytes. Across 18 post-attestation tampering, substitution, provenance and signature attacks, every manipulation is detected in under 16 ms, including a history rewrite re-signed with a legitimate key, at under 1 % of training cost. We then quantify the limit of attestation: a BadNets-poisoned dataset signed by its legitimate steward verifies and deploys with 77 % attack success rate. Pre-attestation content checks flag a known trigger family but are evaded by an adaptive trigger (51 % ASR). We argue that AI supply-chain controls must report cryptographic and semantic evidence separately, and we release the prototype and scenarios for reproducibility.

## Contributions to claim

1. A hash-linked, role-bound attestation chain spanning four AI lifecycle stages, with a policy-enforcing recursive verifier.
2. Row-level dataset Merkle localisation authenticated by the signed root.
3. A reproducible attack suite (26 variants) and a measured demonstration that signed poison verifies.

## Candidate venues (check deadlines and scope before submitting)

- IEEE Conference on Secure and Trustworthy Machine Learning (SaTML)
- ACM Workshop on Artificial Intelligence and Security (AISec, co-located with ACM CCS)
- ACM SCORED (Software Supply Chain Offensive Research and Ecosystem Defenses workshop)
- French venues: C&ESAR (Rennes), RESSI (Rendez-vous de la Recherche et de l'Enseignement de la Sécurité des Systèmes d'Information)

## Format

Short / workshop paper (6–8 pages) with artifact evaluation: repository, Docker image, `attacks/run_all.py` reproduces every table.
