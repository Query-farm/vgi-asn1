# ASN.1 bytes, fields and armor

Three executed notebooks use the native [v0.4.0 release](https://github.com/Query-farm/vgi-asn1/releases/tag/v0.4.0):

1. [Same values, different bytes](01_same_values_different_bytes.ipynb) compares framing normalization, decoded-value groups and the limits of the release's structural DER checks.
2. [Nodes, paths and unknown identifiers](02_nodes_paths_and_unknown_identifiers.ipynb) compares typed JSON, a text trace and path lookups, then preserves unknown OIDs while joining the bundled name registry.
3. [PEM labels and body validation](03_pem_labels_and_body_validation.ipynb) separates an armor label, successful base64 decoding and ASN.1 body parsing. Relabeling a block changes none of its body bytes.

Every notebook has an **Open in Colab** button. In a fresh runtime, run all cells. The short bootstrap installs only the shared base package and downloads the checksum-verified chart companion; it preserves compatible preloaded plotting and kernel packages. No source checkout, Rust compiler, API key or external dataset is required. The worker connection remains visible:

```sql
ATTACH 'asn1' (TYPE vgi,
  LOCATION 'github-auto://Query-farm/vgi-asn1@v0.4.0');
```

GitHub displays saved SQL, results and SVG charts. It does not fold executable inputs using Jupyter metadata, so shared setup remains brief. Editor folding is an optional aid. Presentation, branding and execution are maintained in [vgi-example-notebooks](https://github.com/Query-farm/vgi-example-notebooks), rather than copied into this repo.

## Local execution and experiments

```sh
cd notebooks
uv sync --locked
uv run --locked vgi-notebooks --timeout 300
uv run --locked vgi-notebooks 01_same_values_different_bytes.ipynb \
  --parameters '{"TRIM_BYTES":1}' --output-dir artifacts/trim
uv run --locked vgi-notebooks 02_nodes_paths_and_unknown_identifiers.ipynb \
  --parameters '{"INCLUDE_UNKNOWN":false}' --output-dir artifacts/known
uv run --locked vgi-notebooks 03_pem_labels_and_body_validation.ipynb \
  --parameters '{"FIRST_LABEL":"PUBLIC KEY"}' --output-dir artifacts/relabel
```

The local environment includes the optional runner; the notebook bootstrap installs the base package. Initial package/extension/binary downloads require internet. All parsing then operates on the authored SQL literals. Experiment copies preserve the default saved notebooks.

## Interpretation and coverage

These packets and armor blocks are explicitly synthetic. None contains a real key, certificate or captured message. The worker performs structural parsing and does not verify cryptographic signatures, authenticate data or establish full certificate/key schema validity. Its normalizer preserves primitive payloads, and its DER parser check does not exhaustively enforce DER primitive encoding rules. Those limits are demonstrated in the returned results.

The complete released catalog has **28 logical public functions/tables**, including producer table functions and the OID registry. [Coverage evidence](coverage.json) maps the interpreted examples to 15 of them (target14). Named protocol/security decoders and their fan-outs remain explicit uncovered functions. Current-main source differences are example/documentation metadata; coverage mappings record that compatibility review separately from the actual released notebook runtime. Raw exports, current registration, execution receipts and the reviewed source diff are under [coverage](coverage/).
