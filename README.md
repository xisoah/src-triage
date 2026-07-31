# src-triage

`src-triage` is a lightweight source-code triage tool for reviewing pattern-based security findings. It scans source trees, sends each match to an OpenAI-compatible LLM, and presents the automated and manual verdicts together in a LAN-accessible web dashboard.

The scanner is resumable: every accepted LLM result is written to CSV immediately, and restarting the same job skips findings that have already been processed.

## Features

- Streaming source scan with configurable pattern selection
- One LLM request per matching pattern and source line
- Strict True Positive/False Positive JSON verdict contract
- Automatic retries for endpoint failures or malformed responses
- Pause, item-limit, and restart-safe resume support
- Paginated result table with stable serial numbers
- Search, filtering, sorting, confidence filtering, and saved-job selection
- Full source-context and LLM-response detail viewer
- Independent manual True Positive/False Positive verdicts
- Agreement, disagreement, confidence, and review-progress statistics
- Folder browser and persistent browser settings

## Requirements

- Python 3.9 or newer
- Flask
- Access to an OpenAI-compatible `/v1/chat/completions` endpoint

Install Flask:

```bash
python3 -m pip install flask
```

## Web dashboard

Start the combined LLM and manual reviewer:

```bash
python3 src-triage.py
```

The server listens on all LAN interfaces on port `5001`. Open it locally at:

```text
http://127.0.0.1:5001
```

From another machine on the same network, use the host's LAN address:

```text
http://<host-lan-ip>:5001
```

In the dashboard:

1. Select the source directory.
2. Confirm the endpoint and model.
3. Optionally set a maximum number of new findings or a run label.
4. Uncheck any patterns that should be excluded from the job.
5. Start the scan.
6. Select saved findings in the result table to inspect their context and assign a manual verdict.

Manual-review shortcuts are `T` for True Positive, `F` for False Positive, and the left/right arrow keys for navigation.

## Command-line LLM scanner

The same resumable LLM workflow can run without the dashboard:

```bash
python3 src-triage-cli.py /full/path/to/source
```

Useful options:

```bash
python3 src-triage-cli.py /full/path/to/source \
  --max-items 50 \
  --run-label first-pass \
  --model raktabija:latest \
  --endpoint http://10.13.254.254:11434/v1/chat/completions
```

Run the same command again to resume. Use a different `--run-label` to create an independent review job.

## Patterns

Patterns are loaded from `patterns.txt`. Each non-empty entry is treated as either a case-insensitive literal or a regular expression according to the scanner's pattern detection rules.

Noisy standalone patterns such as `*`, `+`, `?`, `var`, `let`, `Set`, and `Map`, invalid regular expressions, and expressions that match an empty string are excluded automatically. Additional patterns can be unchecked per job in the web dashboard without modifying `patterns.txt`.

## Output data

`results.csv` stores LLM evidence, verdicts, confidence, raw responses, and independent manual verdicts. It is runtime data, is excluded from Git by default, and is migrated automatically when new result columns are introduced.

## Tests

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover pattern matching, context boundaries, endpoint parsing, retries, pause/resume, CSV repair and migration, paginated web results, manual verdicts, navigation, and scan-job isolation.

## Project layout

- `src-triage.py` — primary combined LAN dashboard
- `src-triage-cli.py` — resumable command-line LLM scanner
- `source_scanner.py` — shared pattern loading and streaming matcher
- `patterns.txt` — source-pattern definitions
- `tests/` — automated tests
