# Threat model (v0.1, draft — human review required)

## Assets
- The availability of the host application (CPU, memory, temp disk, worker pool)
- Downstream consumers: storage, previewers, document parsers (PyMuPDF, pdfminer, unstructured,
  docling), embedding/LLM pipelines, and end users who download files
- Privacy of uploaders (location and device metadata)
- Integrity of the guarantee that "the output is what was checked"

## Attacker capabilities
The attacker fully controls the **uploaded bytes, filename, extension, and claimed Content-Type**,
and can send many uploads concurrently. They know IntakeGuard's source code and corpus.
They do **not** control the policy, the host configuration, or the scanner plugins.

## Trust boundaries
1. Network/multipart intake → framework adapter
2. Adapter → engine (binding boundary)
3. Engine → format parsers/transformers (the highest-risk boundary)
4. Engine → artifact store (quarantine vs. output)
5. Engine → scanner plugins (third-party code)
6. Engine → telemetry/report sinks (risk of leaking metadata)

## Abuse cases in scope
| ID | Abuse | Primary control | Fixture family |
|---|---|---|---|
| T1 | Extension/MIME spoofing | Content-based detection + mismatch policy | `type-*` |
| T2 | Executable or script disguised as an allowed type | Allowlist on detected type | `type-*` |
| T3 | Polyglots (valid as two formats) | Polyglot detection | `polyglot-*` |
| T4 | Image bombs (huge declared dimensions) | Header-declared dimension/pixel limits checked before decoding | `img-bomb-*` |
| T5 | Decompression bombs in PDF streams | `maxDecompressedBytes`, streaming inflate with a cap | `pdf-bomb-*` |
| T6 | Oversized input / slowloris streams | Streaming `maxBytes`, `maxProcessingMs` | `limit-*` |
| T7 | PDF active content (JS, Launch, SubmitForm... via OpenAction, AA, annotations, outlines, /Next chains) | Structural inspection; inert-action allowlist; reject everything else | `pdf-active-*` |
| T8 | Evasion via object streams, hex-escaped names, incremental updates | Full structural parse incl. ObjStm, name normalization, all revisions | `pdf-evasion-*` |
| T9 | Embedded files in PDFs | Reject | `pdf-embedded-*` |
| T10 | Encrypted PDFs hiding content | Reject | `pdf-encrypted-*` |
| T11 | Malformed/truncated files crashing downstream parsers | Strict structural validation; reject | `*-truncated`, `*-malformed` |
| T12 | Metadata leak (EXIF GPS, device, XMP) | Decode → re-encode, strip all metadata classes | `img-meta-*` |
| T13 | Use of the original bytes after sanitization | Separate output handle; adapters expose only the output | adapter tests |
| T14 | Parser memory-safety or logic bugs in IntakeGuard itself | Memory-safe core, fuzzing, resource caps, optional process isolation | fuzz corpus |
| T15 | Hidden text aimed at LLMs | **Heuristic warning only** | `pdf-hidden-*` |
| T16 | Policy typo silently weakening protection | Schema rejects unknown fields; strict defaults | spec tests |

## Out of scope (explicitly not defended)
- Malware detection in general (use scanner hooks)
- Exploits against viewers that use only policy-compliant features
- Prompt injection in visible text, or any guarantee about hidden text
- Steganography in pixel data
- Phishing or harmful *content* (what the document says)
- Office, SVG, archive, audio and video formats (rejected as unsupported in v0.1)

## Residual risks
- Bugs in our own parser can make it disagree with downstream parsers about the same file. Mitigation: differential testing; reject on ambiguity.
- Resource limits depend on the host: a binding misconfiguration can weaken T5/T6.
- Re-encoding depends on the image codec, which is itself an attack surface. Fuzz it, and isolate it where possible.
