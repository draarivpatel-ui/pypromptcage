# Threat model

`pypromptcage` assumes an application processes attacker-controlled text and later produces model output that may be rendered or transmitted. The library is a deterministic control at those two text boundaries.

## Assets

- hidden system and developer instructions
- trusted tool definitions and tool results
- credentials, canary tokens, session material, and private keys
- personal data in prompts, retrieved documents, and model output
- the integrity of role and transcript boundaries
- availability of the host process performing scanning

## Attacker capabilities

The attacker can control some or all input text. The attacker may use Unicode control characters, confusable scripts, role delimiters, natural-language instruction overrides, nested encodings, forged structured messages, and output markup. The attacker cannot directly execute code inside the scanner process in this model.

## Security boundaries

1. Input boundary: untrusted text before prompt construction.
2. Output boundary: model output before rendering, publishing, or execution.
3. Resource boundary: scanner memory and CPU consumption under adversarial input.

`pypromptcage` does not cross into tool authorization, network enforcement, or sink-specific output encoding. Those controls remain the application's responsibility.

## Residual risk

Natural-language injection is not fully separable from benign prose. Deterministic scanners have false positives and false negatives. Treat `warn` as a policy decision point and `block` as a high-confidence unsafe result. Even `allow` is not a proof of safety.
