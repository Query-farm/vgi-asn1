# Executable SQL examples

| Notebook | Question |
| --- | --- |
| [Same values, different bytes](01_same_values_different_bytes.ipynb) | Which ASN.1 encoding differences disappear after structural normalization, and which remain? |

The saved example uses seven explicitly synthetic packets and the real
`vgi-asn1` v0.4.0 worker through Haybarn and VGI. It compares validation errors,
raw and normalized byte lengths, and distinct encodings per decoded-value group.
The padded INTEGER illustrates a limit: this release preserves primitive payload
bytes, and its DER parser check is not exhaustive DER conformance validation.
The example does not verify cryptographic signatures.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then copy or
download the entire `notebooks/` directory. No worker source checkout, Rust
compiler, root environment, API key or external dataset is required.

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

The locked environment uses published Haybarn 2.0.0rc11. The visible SQL installs
the community VGI extension and attaches the literal
`github-auto://Query-farm/vgi-asn1@v0.4.0`. Internet access is required to install
dependencies and download the extension and matching platform release asset.
The release includes binaries for Linux, macOS and Windows; the saved executions
were verified on macOS arm64. To upgrade the worker, edit the visible release tag
and rerun both the default and experiment before replacing saved outputs.

For an interactive notebook editor, select `notebooks/.venv/bin/python`. To
register that environment explicitly:

```sh
uv run --frozen python -m ipykernel install --user --name vgi-asn1-notebooks --display-name "Python (vgi-asn1 notebooks)"
```

The runner creates a temporary kernel specification and does not require a
globally registered kernel. It starts from the notebook directory, writes a
default notebook only after all cells succeed, and requires a separate output
directory for overrides.

## Truncation experiment

```sh
uv run --frozen python execute.py --parameters '{"TRIM_BYTES": 1}' --output-dir validation/trim-1
```

This removes one byte from the indefinite-length packet. Compare its error,
available normalization result, and decoded-value group counts. Reset
`TRIM_BYTES = 0` for the default. Experiment copies include the local assets,
helpers, runner and locked environment files. A reader can run the copied folder
independently. Generated charts and execution artifacts are ignored; the primary
notebook retains its successful embedded outputs.

The SQL cells contain the full input fixture and all domain transformations.
Python only handles configuration, presentation, assertions and charts. See
[STANDARD.md](STANDARD.md) for the example presentation conventions.
