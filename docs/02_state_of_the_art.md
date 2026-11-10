# State of the art: AI supply-chain integrity

*Phase 2 deliverable of Projet Applicatif 2 (ESAIP Master 1, referent Sofiane HAMRIOUI). Section owners: attacks and content-level defences, JOGI Sudheer reddy; signing and attestation, MEKALA Rambabu; provenance frameworks, Karan DESHMUKH; documentation and inventory, DAMA Dola Krishna. References were checked in November 2026 for the IEEE paper (`paper/`). The side-by-side comparison is in `03_comparative_table.md`.*

## 1. Why an AI supply chain is not a software supply chain

In a software supply chain, readable source code goes through a build that can be made deterministic: anyone can rebuild the binary and compare it with the one that was shipped. Reproducible builds and build provenance therefore give strong guarantees about what a binary contains.

An AI model is produced differently. Its behaviour comes from data, code, hyper-parameters and randomness, and the result, a file of weights, cannot be read like source code. Training is rarely bit-reproducible, and the only way to learn what a model does is to test it. A deployed model also descends from several parties: a dataset collected by one team, a pretrained model downloaded from a public hub, a fine-tuning run on someone else's infrastructure and a packaging step. Every hand-over is a point where an artifact can be substituted or manipulated, and some manipulations (a backdoor learned from poisoned data) leave no trace that a reviewer could read in the file.

Two consequences shape this project. First, provenance must cover the whole lineage of a model, not one build. Second, even complete provenance proves who produced which bytes; it does not prove that the bytes behave well. Both points recur in every section below.

## 2. Attacks on AI supply chains

### 2.1 Direct poisoning of training and fine-tuning data

BadNets [1] showed that a few training images stamped with a small pixel pattern and relabelled are enough to plant a backdoor: the model keeps its normal accuracy but outputs the attacker's class whenever the pattern is present. Poisoning has since become cheap at scale. Carlini et al. [2] showed that web-scale datasets can be poisoned for tens of dollars, by buying expired domains still referenced by dataset indexes. In 2025, Souly et al. [3] backdoored language models from 600 million to 13 billion parameters with a near-constant number of about 250 poisoned documents, which means larger training sets do not dilute the attack. Poison can enter the base model's training data or a fine-tuning dataset; in both cases it is present before anyone signs the data.

### 2.2 Pre-backdoored and malicious pretrained models

Pretrained models are distributed through public hubs. A model can carry a backdoor in its weights, or attack the machine that loads it. Python's pickle format, used by `torch.save`, executes code during deserialisation. In February 2024 JFrog found about one hundred models on Hugging Face whose pickle files executed code on load, one of them opening a reverse shell [4]. In February 2025 ReversingLabs described models whose deliberately broken pickle stream ran its payload before the security scanner failed [5]. A signature on such a file only proves who published it.

### 2.3 Environment poisoning: dependencies, build and training hosts

The code and infrastructure around training are part of the supply chain. Between 25 and 30 December 2022, a dependency-confusion attack replaced `torchtriton`, a dependency of the PyTorch nightly builds, with a package that exfiltrated SSH keys and files [6]. A compromised training or fine-tuning host can alter weights during training and, if it holds a signing key, sign the result. Software supply-chain controls (pinned dependencies, hardened builders) apply here, but they do not record which dataset and which base model a training run used.

### 2.4 What regulation and risk frameworks ask for

Article 15(5) of the EU AI Act requires, for high-risk systems, measures to prevent, detect, respond to, resolve and control attacks trying to manipulate the training data set (data poisoning) or pre-trained components used in training (model poisoning) [7]. The NIST AI Risk Management Framework [8], MITRE ATLAS technique AML.T0010 *AI supply chain compromise* [9] and the OWASP Machine Learning Security Top 10 (ML06:2023, *ML supply chain attacks*) [10] describe the same risk. None of them prescribes a mechanism; they ask organisations to be able to show where a model came from and that it was not manipulated.

## 3. Cryptographic signing and attestation

A digital signature over an artifact's digest proves that the holder of a private key approved exactly these bytes and that they have not changed since. Ed25519 [11] gives small keys and signatures and fast verification. Two standards define how such evidence is packaged: DSSE [12], an envelope that signs a typed payload, and the in-toto Attestation Framework [13], whose statements bind a subject (a file digest) to a predicate such as build provenance.

Key management is the hard part of signing. **Sigstore** [14] removes long-lived keys: Fulcio issues short-lived certificates bound to an OpenID Connect identity, Rekor records every signature in a public transparency log, and `cosign` signs and verifies. Keyless signing trades key custody for a dependency on public infrastructure and an identity provider. **OpenSSF Model Signing (OMS)** v1.0 [15], released in April 2025, applies this to machine-learning models: it signs a model directory, file by file, with Sigstore or a private PKI.

These tools prove the integrity and origin of one artifact. They do not link a fine-tuned model to the dataset and base model it was trained from, they do not say which identity may sign which stage, and they say nothing about what a model learned.

## 4. Provenance frameworks and tamper-evident logs

**SLSA** v1.1 [16] defines levels of build provenance, from documented builds to non-forgeable provenance produced by hardened builders. Applied to ML, training plays the role of the build and the dataset and base model are build inputs, but SLSA describes one build step, not a chain of training and fine-tuning steps owned by different parties.

**in-toto** [17] is the closest conceptual match to this project: a project owner signs a *layout* that lists the steps of a supply chain, which functionary may perform each step and which materials and products link the steps; a verifier checks that the evidence follows the layout. in-toto was designed for software builds; its layouts do not model dataset content or revocation along an AI lineage.

**The Update Framework (TUF)** [18] showed how to survive key compromise with separate roles, thresholds and explicit revocation, and **Certificate Transparency** [19] showed how a Merkle-tree log makes history append-only and auditable: anyone can check that a record is included and that the log was only extended. Merkle trees also allow a dataset to be committed row by row, so a single changed row can be located.

**Blockchain anchoring** gives a public, tamper-evident timeline, at the cost of operating or paying for a ledger and of trusting its consensus. For a single organisation, a signed, hash-chained log with a pinned head gives the same append-only property with far less infrastructure; a public anchor or transparency log becomes useful when several organisations must agree on one history.

## 5. Documentation and inventory

**Model cards** [20] and **datasheets for datasets** [21] document intended use, training data and evaluation. **ML bills of materials** list the components of an AI system: CycloneDX added ML-BOM support in version 1.5 (June 2023) [22], and SPDX 3.0 (April 2024) introduced AI and Dataset profiles [23]. These documents bring transparency, not integrity: they are unsigned by default, and their value depends on someone signing them and checking them before deployment.

## 6. Content-level defences

Content-level defences look at what the data or the model contains. On the data side, they include validation, label-distribution tests and outlier detection. On the model side, backdoor detection methods include activation clustering [24], spectral signatures [25], Neural Cleanse [26], which reverse-engineers candidate triggers, and STRIP [27], which perturbs inputs at run time. All of them give evidence, not proof: adaptive attackers choose triggers that a given detector does not model, clean-label poisoning leaves labels untouched, and every detector has false positives and a cost. They are complementary to signatures and cannot replace them, and signatures cannot replace them either.

## 7. Safe serialisation

The pickle attacks of section 2.2 are prevented by formats that cannot execute code. **safetensors** [28] stores a JSON header and raw tensors; it was audited by Trail of Bits in 2023. Scanners for pickle files exist, but section 2.2 shows they can be evaded, so refusing pickle formats at deployment is the safer rule.

## 8. Open-source, industrial and academic approaches compared

`03_comparative_table.md` compares the approaches capability by capability. In short:

- **Open-source signing and provenance** (Sigstore and `cosign`, OMS, in-toto, SLSA, TUF) gives mature, interoperable integrity and origin for individual artifacts and builds, and the transparency-log and key-compromise techniques this project reuses.
- **Industrial practice** on model hubs combines safe formats (safetensors) with scanning of uploaded files; it reduces code-execution risk on load but does not establish lineage or semantic safety.
- **Academic work** measures poisoning and proposes backdoor detectors; it shows that content checks are partial and attackable, and that poisoning is cheap.

## 9. Limitations of the state of the art

1. **No end-to-end lineage.** Existing tools sign one file or one build. Nothing links dataset, base model, fine-tuned model and deployment into one verifiable graph, decides which role may sign which stage, revokes along the links, or gates deployment on the whole chain.
2. **Unsigned metadata.** Lineage kept as ordinary database state can be edited by whoever administers the database.
3. **Signed is read as safe.** A valid signature is often presented to users as a safety signal, but no work we found measures how much protection it gives against poison that was present before signing.
4. **Content checks are partial.** They are evadable and must be reported as separate, weaker evidence.

## 10. Selected approach and justification

AI-ChainGuard keeps the proven building blocks and adds what is missing for AI lineage:

| Choice | Justification |
| --- | --- |
| Ed25519-signed JSON manifests with canonical serialisation (RFC 8785-style [29]) | Small, fast, deterministic signatures; one manifest per artifact; exportable as in-toto statements in DSSE envelopes for interoperability |
| Each manifest embeds the manifest digests of its parents | Turns separate signatures into one hash-linked provenance graph: rewriting an ancestor breaks every descendant, even with a legitimate key |
| Row-level Merkle root for datasets (RFC 6962 style) | Detects and locates a single changed row |
| Role-bound signers and a stage policy | Applies the in-toto layout idea to AI stages: the training key cannot sign datasets, a fine-tuned model needs a dataset and a base model |
| Signed, hash-chained, pinned trust log for keys and revocation | Append-only history and revocation without operating a blockchain; the database is only an untrusted index |
| Deployment gateway that verifies the whole chain and loads the verified bytes; safetensors only | Closes the time-of-check to time-of-use gap and the pickle code-execution path |
| Content checks reported separately (WARNING), never as proof | Keeps cryptographic and semantic evidence apart, which is the point the project measures |
| Custom signing instead of Sigstore at the core | Works offline and locally, with the role policy and parent links described above; an optional Sigstore keyless signing job is included in the CI workflow (off by default) |

## References

1. T. Gu, B. Dolan-Gavitt and S. Garg, "BadNets: Identifying vulnerabilities in the machine learning model supply chain," arXiv:1708.06733, 2017.
2. N. Carlini et al., "Poisoning web-scale training datasets is practical," IEEE Symp. Security and Privacy, 2024, pp. 407–425.
3. A. Souly et al., "Poisoning attacks on LLMs require a near-constant number of poison samples," arXiv:2510.07192, Oct. 2025.
4. D. Cohen, JFrog Security Research, "Data scientists targeted by malicious Hugging Face ML models with silent backdoor," Feb. 2024.
5. K. Zanki, ReversingLabs, "Malicious ML models discovered on Hugging Face platform," Feb. 2025.
6. PyTorch team, "Compromised PyTorch-nightly dependency chain between December 25th and December 30th, 2022," Dec. 31, 2022.
7. Regulation (EU) 2024/1689 (Artificial Intelligence Act), Off. J. EU, 12 July 2024, Art. 15(5).
8. NIST, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023.
9. MITRE ATLAS, technique AML.T0010, "AI supply chain compromise."
10. OWASP, "Machine Learning Security Top 10," ML06:2023 ML supply chain attacks.
11. S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, Jan. 2017.
12. Secure Systems Lab, "DSSE: Dead Simple Signing Envelope," protocol v1.
13. in-toto project, "in-toto Attestation Framework: Statement v1."
14. Z. Newman, J. S. Meyers and S. Torres-Arias, "Sigstore: Software signing for everybody," ACM CCS, 2022, pp. 2353–2367.
15. OpenSSF, "Model Signing v1.0," Apr. 2025.
16. OpenSSF, "SLSA specification v1.1," Apr. 2025.
17. S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola and J. Cappos, "in-toto: Providing farm-to-table guarantees for bits and bytes," USENIX Security, 2019, pp. 1393–1410.
18. J. Samuel, N. Mathewson, J. Cappos and R. Dingledine, "Survivable key compromise in software update systems," ACM CCS, 2010, pp. 61–72.
19. B. Laurie, A. Langley and E. Kasper, "Certificate Transparency," RFC 6962, Jun. 2013.
20. M. Mitchell et al., "Model cards for model reporting," FAT*, 2019, pp. 220–229.
21. T. Gebru et al., "Datasheets for datasets," Commun. ACM, vol. 64, no. 12, pp. 86–92, 2021.
22. OWASP CycloneDX, "CycloneDX v1.5 released," June 2023 (machine-learning bill of materials).
23. Linux Foundation, "SPDX 3.0" release announcement, April 2024 (AI and Dataset profiles).
24. B. Chen et al., "Detecting backdoor attacks on deep neural networks by activation clustering," AAAI Workshop SafeAI, 2019.
25. B. Tran, J. Li and A. Madry, "Spectral signatures in backdoor attacks," NeurIPS, vol. 31, 2018.
26. B. Wang et al., "Neural Cleanse: Identifying and mitigating backdoor attacks in neural networks," IEEE Symp. Security and Privacy, 2019, pp. 707–723.
27. Y. Gao, C. Xu, D. Wang, S. Chen, D. C. Ranasinghe and S. Nepal, "STRIP: A defence against trojan attacks on deep neural networks," ACSAC, 2019, pp. 113–125.
28. Hugging Face, "Safetensors" documentation; security audit by Trail of Bits, 2023.
29. A. Rundgren, B. Jordan and S. Erdtman, "JSON Canonicalization Scheme (JCS)," RFC 8785, Jun. 2020.
