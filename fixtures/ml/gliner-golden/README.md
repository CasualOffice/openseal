# GLiNER golden spans (ML-07, ML-08)

Reference output of the Python `gliner` package (0.2.29, pinned in `tools/ml/requirements.txt`) for the Rust
GLiNER decoder in `casual-sign-modeld` (docs/33 §5.3 and §5.4). Made by:

    python3 -I tools/ml/export-gliner.py fetch  --work DIR
    VENV/bin/python -I tools/ml/export-gliner.py export --work DIR
    VENV/bin/python -I tools/ml/export-gliner.py golden --work DIR
    python3 -I tools/ml/export-gliner.py check      # shape and offsets of these files, no network

- `texts.json`: 50 synthetic texts in NFC: 40 English agreement and contact snippets, then French, German,
  Spanish, Italian, Portuguese, Dutch, Polish, Swedish, Arabic and Hindi. Every name, company, address, phone
  number, email, account, card and id is invented or comes from a reserved test range. No entry belongs to a
  real person.
- `<model>.json`, one per exported model: the labels, threshold (0.5), `flat_ner`, the SHA-256 of each
  exported ONNX file and of `tokenizer.json`, then per text:
  - `words`: gliner's whitespace word split, as `[word, start, end]` in code points.
  - `onnx_inputs`: the exact ONNX feeds, namely `input_ids`, `words_mask`, `text_lengths`, the
    `attention_mask` sum, and every feed's shape and dtype.
  - `spans`: one list per variant. `torch` is PyTorch on the source weights. `onnx_fp32`, `onnx_fp16` and
    `onnx_quint8` are each exported file run with ONNX Runtime 1.31.1 on CPU, one intra-op thread.
- Span offsets: `start`/`end` count code points and `start_byte`/`end_byte` count UTF-8 bytes, both into the
  NFC text.
- `agreement_with_torch` measures what each export costs against the PyTorch reference.

The ONNX files are not committed. Their hashes are in each file and go into `tools/ml/models.toml`.
