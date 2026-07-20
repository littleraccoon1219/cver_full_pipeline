# M1 candidate and human annotation workflow

Collected CVE/GHSA/vendor advisory/security-fix/non-security-bug materials enter `data/candidates/` as content-addressed, untrusted bundles. No model-generated label is admitted as ground truth.

A human annotation must include:

- exactly one primary RC-1..RC-5 and one matching primary second-level label, or `UNKNOWN/NEEDS_REVIEW`;
- at least two independent evidence IDs for a non-UNKNOWN primary cause;
- the first failed invariant in the minimal causal chain;
- a true counterfactual statement that repairing the primary failure changes the outcome;
- any number of secondary causes, each with independent evidence, a causal role, and its own counterfactual test;
- one primary SP1-SP13 property for confirmed security vulnerabilities;
- a written rationale and annotator identity.

Test-set records and all records sharing their split group must be excluded from RAG and few-shot retrieval.
