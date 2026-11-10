# Conference proposal

*Common-framework deliverable of the ESAIP Master 1 applied projects: title, abstract and targeted venue. Final version, 10 November 2026. The full six-page paper in IEEE conference format, in English and in French, is in `paper/`.*

## Title

**Signed Is Not Safe: Measuring the Boundary Between Cryptographic Integrity and Semantic Trust in AI Supply Chains**

**Authors:** Karan Deshmukh, Sudheer Reddy Jogi, Dola Krishna Dama, Rambabu Mekala (ESAIP, Angers). Supervisor: Sofiane HAMRIOUI.

## Abstract

A deployed model is the product of datasets, pretrained weights and fine-tuning steps from different parties, yet software supply-chain controls sign one build or one file and say nothing about this lineage or about what a valid signature means for a model's behaviour. We present AI-ChainGuard, which gives every artifact of an AI pipeline, from dataset to deployment record, a signed manifest whose payload embeds the manifest digests of its parents. The result is a hash-linked provenance graph that a verifier validates with ten checks. Trust and revocation live in a signed, pinned, append-only log, and a deployment gateway verifies the whole chain at deployment time before loading a model from the verified bytes. We then measure the boundary of such guarantees with a reproducible suite of 48 attack and control variants in seven experiments. Every post-signing manipulation in the suite, from a 10⁻⁶ change to one weight to the truncation of the trust log, is detected in 1.7–15.1 ms including the chain. But a dataset poisoned before signing verifies and deploys with a 77 % backdoor success rate behind a VERIFIED status, an adaptive trigger evades content heuristics at 51 %, and a trusted publisher's backdoored model verifies with 100 %. Attestation costs 0.8 % of training time, 8.5 ms per full-chain verification, nothing per inference and 1.4–3.1 KB per manifest, and exports as in-toto/DSSE attestations with ChainGuard or SLSA predicates. We argue that AI supply-chain controls must report cryptographic and semantic evidence separately, and release code, tests and scenarios.

**Keywords:** AI supply chain, attestation, backdoor, data poisoning, digital signatures, in-toto, model provenance, revocation, SLSA, software supply chain security.

## Contributions

1. A hash-linked, role-bound attestation chain over four AI lifecycle stages, with a policy-enforcing recursive verifier (checks V0 to V9), a signed and pinned trust log for keys and revocation, and a deployment gateway that loads the verified bytes.
2. Row-level dataset Merkle roots that locate a changed row, authenticated by the signed manifest.
3. A reproducible suite of 48 attack and control variants in seven experiments, with the measured result that signed poison verifies and deploys, and that content checks are partial evidence.
4. Measured cost and interoperability: overhead per stage, per verification and per inference, and export to in-toto/DSSE.

## Targeted venues

| Venue | Why it fits | Format |
| --- | --- | --- |
| **ACM SCORED** (Software Supply Chain Offensive Research and Ecosystem Defenses), co-located with ACM CCS | Software supply-chain security; attestation, in-toto, SLSA, Sigstore | Workshop paper |
| **ACM AISec** (Workshop on Artificial Intelligence and Security), co-located with ACM CCS | Security of machine-learning systems, poisoning and backdoors | Workshop paper |
| **IEEE SaTML** (Conference on Secure and Trustworthy Machine Learning) | Trustworthy ML, measurement of defences | Conference paper |
| **C&ESAR** (Rennes) or **RESSI** (French venues) | French security research and teaching community; a French version of the paper exists | Conference or short paper |

First choice: **ACM SCORED**, because the contribution is a supply-chain mechanism and a measurement of its boundary. Deadlines and page limits must be checked on each venue's call for papers before submitting.

## Format and artifacts

A six-page paper in IEEE conference format (English and French versions in `paper/`), extendable to the venue's page limit. Artifact evaluation: the public repository, the Docker image, the 168 tests and `python -m attacks.run_all`, which regenerates every table of the evaluation.
