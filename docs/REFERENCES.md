# Standards and related-work anchors

Selected primary sources reviewed during preparation on 15 October 2026. This is not an exhaustive prior-art search, endorsement or proof of uniqueness.

- [NIST SP 800-207, Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final): policy/enforcement and resource-oriented trust foundations.
- [SPIFFE overview](https://spiffe.io/docs/latest/spiffe-about/overview/): workload identity building blocks.
- [RFC 9449, OAuth DPoP](https://www.rfc-editor.org/rfc/rfc9449.html): sender-constrained token mechanisms.
- [RFC 8705, OAuth mTLS](https://www.rfc-editor.org/rfc/rfc8705.html): certificate-bound access tokens.
- [RFC 8693, OAuth Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html): delegation-related building blocks.
- [RFC 9334, RATS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html): attestation roles and evidence.
- [NIST NCCoE agent identity project](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) and [public-comment synthesis](https://pages.nist.gov/nccoe-ai-identity/summary-of-comments.html): existing identity foundations, task context and delegation challenges.
- [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/): threat taxonomy; not certification of this design.
- [Agentic-ZTA, Roy et al.](https://arxiv.org/abs/2610.05782): related multi-agent zero-trust research. Its implementation was not reproduced here.
- [Z3 project](https://github.com/Z3Prover/z3): formal solver used for this repository's abstraction checks.

The standard mechanisms overlap with AA-ZTCE's building blocks. A previous self-authored, feature-matched policy comparison produced matching decisions; it did not demonstrate superior real-world security. Any distinctive contribution of the integrated architecture remains a research question requiring systematic comparison and independent evaluation.
