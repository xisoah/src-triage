#!/usr/bin/env python3

import csv
import importlib.util
import os
import threading
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from flask import Flask, jsonify, render_template_string, request

from source_scanner import (
    BASE_DIR,
    IGNORE_DIRS,
    PATTERNS_FILE,
    generate_matches,
    load_patterns,
    new_scan_stats,
)


def load_llm_module():
    script_path = os.path.join(BASE_DIR, "src-triage-cli.py")
    spec = importlib.util.spec_from_file_location("src_triage_cli_core", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


llm = load_llm_module()
app = Flask(__name__)

WEB_PATTERNS_FILE = PATTERNS_FILE
WEB_RESULTS_FILE = llm.DEFAULT_OUTPUT
STATE_LOCK = threading.Lock()
RESULTS_LOCK = threading.Lock()

web_state = {
    "token": None,
    "thread": None,
    "stop_event": None,
    "status": "idle",
    "job_id": None,
    "target_directory": None,
    "reviewed": 0,
    "resumed": 0,
    "stats": new_scan_stats(),
    "error": None,
    "events": [],
    "event_sequence": 0,
}


def public_state(after=0):
    with STATE_LOCK:
        stats = dict(web_state["stats"])
        stats["errors"] = [
            dict(error) for error in web_state["stats"].get("errors", [])
        ]
        return {
            "status": web_state["status"],
            "job_id": web_state["job_id"],
            "target_directory": web_state["target_directory"],
            "reviewed": web_state["reviewed"],
            "resumed": web_state["resumed"],
            "stats": stats,
            "error": web_state["error"],
            "event_sequence": web_state["event_sequence"],
            "events": [
                event for event in web_state["events"]
                if event["sequence"] > after
            ],
        }


def update_state(token, **changes):
    with STATE_LOCK:
        if web_state["token"] != token:
            return
        web_state.update(changes)


def add_event(token, event_type, data):
    with STATE_LOCK:
        if web_state["token"] != token:
            return
        web_state["event_sequence"] += 1
        web_state["events"].append({
            "sequence": web_state["event_sequence"],
            "type": event_type,
            "data": data,
        })
        if len(web_state["events"]) > 2000:
            del web_state["events"][:-2000]


def finding_for_browser(finding):
    return {
        "filepath": finding["filepath"],
        "line_num": finding["line_num"],
        "pattern": finding["pattern"],
        "context": finding["context"],
    }


def run_web_scan(token, stop_event, target_dir, patterns, args, existing_rows):
    job_id = llm.build_job_id(target_dir, patterns, args)
    completed = {
        row["Finding ID"]
        for row in existing_rows
        if row["Job ID"] == job_id
    }
    stats = new_scan_stats()
    reviewed = 0
    resumed = 0

    update_state(
        token,
        status="running",
        job_id=job_id,
        stats=stats,
        reviewed=0,
        resumed=0,
        error=None,
    )

    matches = generate_matches(
        target_dir,
        patterns,
        stats,
        all_matches_per_line=True,
        context_radius=llm.CONTEXT_RADIUS,
    )
    try:
        for finding in matches:
            if stop_event.is_set():
                update_state(
                    token,
                    status="paused",
                    reviewed=reviewed,
                    resumed=resumed,
                    stats=stats,
                )
                return

            finding_id = llm.build_finding_id(job_id, finding)
            if finding_id in completed:
                resumed += 1
                update_state(token, resumed=resumed, stats=stats)
                continue

            add_event(token, "reviewing", finding_for_browser(finding))

            def on_retry(attempt, total_attempts, delay, error):
                add_event(token, "retry", {
                    "attempt": attempt,
                    "total_attempts": total_attempts,
                    "delay": delay,
                    "error": str(error),
                })

            try:
                verdict_data, raw_response = llm.review_with_retries(
                    finding,
                    args,
                    on_retry=on_retry,
                )
            except llm.LLMReviewError as exc:
                message = (
                    f"{finding['filepath']}:{finding['line_num']}: {exc}"
                )
                add_event(token, "error", {"message": message})
                update_state(
                    token,
                    status="error",
                    error=message,
                    reviewed=reviewed,
                    resumed=resumed,
                    stats=stats,
                )
                return

            row = llm.make_result_row(
                job_id,
                args.run_label,
                target_dir,
                finding_id,
                finding,
                verdict_data,
                raw_response,
                args.model,
            )
            with RESULTS_LOCK:
                llm.append_result(args.output, row)
            completed.add(finding_id)
            reviewed += 1
            add_event(token, "result", {
                "job_id": job_id,
                "finding_id": finding_id,
            })
            update_state(
                token,
                reviewed=reviewed,
                resumed=resumed,
                stats=stats,
            )

            if args.max_items is not None and reviewed >= args.max_items:
                update_state(
                    token,
                    status="paused",
                    reviewed=reviewed,
                    resumed=resumed,
                    stats=stats,
                )
                return

        update_state(
            token,
            status="complete",
            reviewed=reviewed,
            resumed=resumed,
            stats=stats,
        )
    except Exception as exc:
        message = str(exc)
        add_event(token, "error", {"message": message})
        update_state(
            token,
            status="error",
            error=message,
            reviewed=reviewed,
            resumed=resumed,
            stats=stats,
        )
    finally:
        matches.close()


def load_result_rows():
    with RESULTS_LOCK:
        return llm.initialize_results(WEB_RESULTS_FILE)[0]


def numbered_job_rows(rows, job_id):
    numbered = []
    serial = 0
    for row in rows:
        if row["Job ID"] != job_id:
            continue
        serial += 1
        numbered.append({"Serial Number": serial, **row})
    return numbered


def result_summary(rows):
    summary = {
        "total": len(rows),
        "llm_true_positive": 0,
        "llm_false_positive": 0,
        "manual_true_positive": 0,
        "manual_false_positive": 0,
        "manual_unreviewed": 0,
        "agreement": 0,
        "disagreement": 0,
        "average_confidence": None,
    }
    confidences = []
    for row in rows:
        if row["Verdict"] == "True Positive":
            summary["llm_true_positive"] += 1
        elif row["Verdict"] == "False Positive":
            summary["llm_false_positive"] += 1

        manual = row.get("Manual Verdict", "")
        if manual == "True Positive":
            summary["manual_true_positive"] += 1
        elif manual == "False Positive":
            summary["manual_false_positive"] += 1
        else:
            summary["manual_unreviewed"] += 1
        if manual:
            if manual == row["Verdict"]:
                summary["agreement"] += 1
            else:
                summary["disagreement"] += 1

        try:
            confidences.append(float(row["Confidence"]))
        except (TypeError, ValueError):
            pass
    if confidences:
        summary["average_confidence"] = sum(confidences) / len(confidences)
    return summary


def filter_and_sort_rows(rows, options):
    query = str(options.get("query", "")).strip().lower()
    llm_verdict = str(options.get("llm_verdict", "")).strip()
    manual_verdict = str(options.get("manual_verdict", "")).strip()
    pattern = str(options.get("pattern", "")).strip().lower()
    try:
        confidence_min = float(options.get("confidence_min", ""))
    except (TypeError, ValueError):
        confidence_min = None
    try:
        confidence_max = float(options.get("confidence_max", ""))
    except (TypeError, ValueError):
        confidence_max = None

    filtered = []
    for row in rows:
        searchable = " ".join([
            row.get("Matched Pattern", ""),
            row.get("Filename", ""),
            row.get("Reason", ""),
            row.get("Matched Line", ""),
        ]).lower()
        if query and query not in searchable:
            continue
        if pattern and pattern not in row.get("Matched Pattern", "").lower():
            continue
        if llm_verdict and row.get("Verdict") != llm_verdict:
            continue
        manual = row.get("Manual Verdict", "")
        if manual_verdict == "Unreviewed" and manual:
            continue
        if manual_verdict and manual_verdict != "Unreviewed" and manual != manual_verdict:
            continue
        try:
            confidence = float(row.get("Confidence", ""))
        except (TypeError, ValueError):
            confidence = None
        if confidence_min is not None and (
            confidence is None or confidence < confidence_min
        ):
            continue
        if confidence_max is not None and (
            confidence is None or confidence > confidence_max
        ):
            continue
        filtered.append(row)

    sort_name = str(options.get("sort", "serial"))
    direction = str(options.get("direction", "asc"))
    def safe_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def safe_float(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return -1.0

    sorters = {
        "serial": lambda row: row["Serial Number"],
        "pattern": lambda row: row.get("Matched Pattern", "").lower(),
        "file": lambda row: row.get("Filename", "").lower(),
        "line": lambda row: safe_int(row.get("Line Number")),
        "llm_verdict": lambda row: row.get("Verdict", ""),
        "manual_verdict": lambda row: row.get("Manual Verdict", ""),
        "confidence": lambda row: safe_float(row.get("Confidence")),
    }
    key = sorters.get(sort_name, sorters["serial"])
    return sorted(filtered, key=key, reverse=direction == "desc")


def lightweight_result(row):
    return {
        "Serial Number": row["Serial Number"],
        "Job ID": row["Job ID"],
        "Finding ID": row["Finding ID"],
        "Matched Pattern": row["Matched Pattern"],
        "Filename": row["Filename"],
        "File Name": os.path.basename(row["Filename"]),
        "Line Number": row["Line Number"],
        "Verdict": row["Verdict"],
        "Manual Verdict": row.get("Manual Verdict", ""),
        "Reason": row["Reason"],
        "Confidence": row["Confidence"],
        "Reviewed At": row["Reviewed At"],
        "Manual Reviewed At": row.get("Manual Reviewed At", ""),
    }


def find_result(rows, job_id, finding_id):
    for row in numbered_job_rows(rows, job_id):
        if row["Finding ID"] == finding_id:
            return row
    return None


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>src-triage</title>
    <style>
        :root {
            --bg:#11111b; --panel:#181825; --surface:#1e1e2e; --border:#313244;
            --text:#cdd6f4; --muted:#9399b2; --blue:#89b4fa; --green:#a6e3a1;
            --red:#f38ba8; --yellow:#f9e2af; --purple:#cba6f7;
        }
        * { box-sizing:border-box; }
        body { margin:0; padding:18px; background:var(--bg); color:var(--text); font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace; }
        h1,h2,h3 { margin:0 0 12px; } h1 { color:var(--blue); font-size:22px; } h2 { font-size:16px; } h3 { font-size:14px; }
        .panel { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:14px; }
        details > summary { cursor:pointer; color:var(--blue); font-weight:700; margin:-2px 0 12px; }
        .config-grid { display:grid; grid-template-columns:minmax(340px,1fr) minmax(340px,1fr); gap:14px; }
        .grid { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
        .field { margin-bottom:9px; } label { display:block; color:var(--muted); margin-bottom:4px; }
        input,select { width:100%; padding:8px; background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:4px; font:inherit; }
        button { padding:8px 11px; border:0; border-radius:4px; cursor:pointer; background:var(--blue); color:var(--bg); font-weight:700; }
        button.secondary { background:#45475a; color:var(--text); } button.tp { background:var(--green); } button.fp { background:var(--red); }
        button.clear { background:var(--yellow); } button:disabled { opacity:.45; cursor:not-allowed; }
        .row,.actions,.status-line,.pagination { display:flex; align-items:center; gap:8px; } .row input { flex:1; }
        .status-line { justify-content:space-between; } .status { color:var(--blue); font-weight:700; text-transform:uppercase; }
        .meta { color:var(--muted); font-size:12px; overflow-wrap:anywhere; } .notice { color:var(--yellow); font-size:12px; margin-top:7px; }
        .pattern-list { height:225px; overflow:auto; background:var(--bg); border:1px solid var(--border); border-radius:4px; padding:7px; }
        .pattern { display:flex; align-items:flex-start; gap:7px; padding:3px; overflow-wrap:anywhere; } .pattern input { width:auto; margin-top:3px; }
        .stats { display:grid; grid-template-columns:repeat(5,minmax(110px,1fr)); gap:8px; margin:10px 0; }
        .stat { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:10px; }
        .stat strong { display:block; font-size:19px; color:var(--blue); } .stat span { color:var(--muted); font-size:11px; }
        .filter-grid { display:grid; grid-template-columns:2fr 1fr 1fr 1fr 90px 90px 130px 90px; gap:7px; align-items:end; }
        .table-wrap { height:430px; overflow:auto; border:1px solid var(--border); border-radius:5px; background:var(--bg); }
        table { width:100%; border-collapse:collapse; table-layout:fixed; }
        th { position:sticky; top:0; z-index:2; background:var(--surface); color:var(--blue); text-align:left; padding:8px; border-bottom:1px solid var(--border); }
        td { padding:7px 8px; border-bottom:1px solid var(--border); vertical-align:top; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        tbody tr { cursor:pointer; } tbody tr:hover,tbody tr.selected { background:#25253a; }
        .c-sr{width:60px}.c-pattern{width:15%}.c-file{width:18%}.c-line{width:75px}.c-verdict{width:140px}.c-reason{width:auto}.c-confidence{width:90px}
        .badge { display:inline-block; padding:2px 6px; border-radius:10px; font-size:11px; font-weight:700; }
        .badge.tp { background:rgba(166,227,161,.16); color:var(--green); } .badge.fp { background:rgba(243,139,168,.16); color:var(--red); }
        .badge.pending { background:rgba(249,226,175,.14); color:var(--yellow); }
        .pagination { justify-content:flex-end; margin-top:9px; } .pagination span { color:var(--muted); }
        .detail-grid { display:grid; grid-template-columns:minmax(0,3fr) minmax(270px,1fr); gap:12px; }
        .detail-meta { display:grid; grid-template-columns:120px 1fr; gap:5px 10px; margin:9px 0; }
        .detail-meta dt { color:var(--muted); } .detail-meta dd { margin:0; overflow-wrap:anywhere; }
        pre { margin:8px 0 0; padding:11px; max-height:390px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; background:var(--bg); border:1px solid var(--border); border-radius:5px; }
        .reason { background:var(--bg); border:1px solid var(--border); border-radius:5px; padding:10px; margin-top:8px; }
        .empty { color:var(--muted); text-align:center; padding:35px; }
        .modal { display:none; position:fixed; inset:0; z-index:20; background:rgba(0,0,0,.65); align-items:center; justify-content:center; }
        .modal.open { display:flex; } .modal-card { width:min(650px,92vw); max-height:80vh; display:flex; flex-direction:column; background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:16px; }
        .folder-list { overflow:auto; margin:10px 0; } .folder { padding:8px; margin-bottom:5px; background:var(--bg); border:1px solid var(--border); border-radius:4px; cursor:pointer; }
        @media(max-width:1100px){.config-grid,.detail-grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.filter-grid{grid-template-columns:repeat(2,1fr)}}
    </style>
</head>
<body>
    <h1>src-triage</h1>

    <details class="panel" open>
        <summary>Scan configuration</summary>
        <div class="config-grid">
            <section>
                <div class="field"><label>Target directory</label><div class="row"><input id="directory" placeholder="/full/path/to/source"><button class="secondary" onclick="openBrowser()">Browse</button></div></div>
                <div class="grid">
                    <div class="field"><label>Model</label><input id="model" value="raktabija:latest"></div>
                    <div class="field"><label>Max new items (blank = all)</label><input id="maxItems" type="number" min="1"></div>
                </div>
                <div class="field"><label>Endpoint</label><input id="endpoint" value="http://10.13.254.254:11434/v1/chat/completions"></div>
                <div class="field"><label>Run label</label><input id="runLabel" placeholder="Change for a fresh review"></div>
                <div class="grid">
                    <div class="field"><label>Temperature</label><input id="temperature" type="number" min="0" max="2" step=".1" value="0.2"></div>
                    <div class="field"><label>Max tokens</label><input id="maxTokens" type="number" min="1" value="500"></div>
                    <div class="field"><label>Timeout seconds</label><input id="timeout" type="number" min="1" value="120"></div>
                    <div class="field"><label>Retries</label><input id="retries" type="number" min="0" value="3"></div>
                </div>
                <div class="actions"><button id="startButton" onclick="startScan()">Start / Resume Scan</button><button id="pauseButton" class="clear" onclick="pauseScan()" disabled>Pause</button></div>
            </section>
            <section>
                <h3>Patterns</h3>
                <div class="field"><input id="patternSearch" placeholder="Filter patterns" oninput="filterPatterns()"></div>
                <div class="actions"><button class="secondary" onclick="toggleVisible(true)">Include visible</button><button class="secondary" onclick="toggleVisible(false)">Exclude visible</button><span id="patternCount" class="meta"></span></div>
                <div id="patternNotice" class="notice"></div>
                <div id="patternList" class="pattern-list">Loading patterns…</div>
            </section>
        </div>
    </details>

    <section class="panel">
        <div class="status-line"><span id="status" class="status">Idle</span><span id="jobId" class="meta"></span></div>
        <div id="liveSummary" class="meta" style="margin-top:8px">No scan running.</div><div id="error" class="notice"></div>
        <details style="margin-top:10px"><summary>Current LLM finding</summary><div id="currentMeta" class="meta">Waiting…</div><pre id="currentContext">No finding is being processed.</pre></details>
    </section>

    <section class="panel">
        <div class="grid"><div class="field"><label>Saved job</label><select id="jobSelect" onchange="changeJob()"><option value="">No saved jobs</option></select></div><div class="field"><label>Selected job target</label><input id="jobTarget" readonly></div></div>
        <div id="stats" class="stats"></div>
        <div class="filter-grid">
            <div class="field"><label>Search</label><input id="resultQuery" placeholder="Pattern, file, reason…" oninput="scheduleResultsReload()"></div>
            <div class="field"><label>LLM verdict</label><select id="llmFilter" onchange="filtersChanged()"><option value="">All</option><option>True Positive</option><option>False Positive</option></select></div>
            <div class="field"><label>Manual verdict</label><select id="manualFilter" onchange="filtersChanged()"><option value="">All</option><option>Unreviewed</option><option>True Positive</option><option>False Positive</option></select></div>
            <div class="field"><label>Pattern</label><input id="resultPattern" oninput="scheduleResultsReload()"></div>
            <div class="field"><label>Min conf.</label><input id="confidenceMin" type="number" min="0" max="1" step=".1" onchange="filtersChanged()"></div>
            <div class="field"><label>Max conf.</label><input id="confidenceMax" type="number" min="0" max="1" step=".1" onchange="filtersChanged()"></div>
            <div class="field"><label>Sort</label><select id="sort" onchange="filtersChanged()"><option value="serial">Sr. No.</option><option value="confidence">Confidence</option><option value="pattern">Pattern</option><option value="file">File</option><option value="line">Line</option><option value="llm_verdict">LLM verdict</option><option value="manual_verdict">Manual verdict</option></select></div>
            <div class="field"><label>Direction</label><select id="direction" onchange="filtersChanged()"><option value="asc">Ascending</option><option value="desc">Descending</option></select></div>
        </div>
        <div class="table-wrap">
            <table><thead><tr><th class="c-sr">Sr.</th><th class="c-pattern">Pattern</th><th class="c-file">File</th><th class="c-line">Line</th><th class="c-verdict">LLM verdict</th><th class="c-verdict">Manual verdict</th><th class="c-reason">Reason</th><th class="c-confidence">Confidence</th></tr></thead><tbody id="resultBody"><tr><td colspan="8" class="empty">Choose a saved job or start a scan.</td></tr></tbody></table>
        </div>
        <div class="pagination"><select id="pageSize" style="width:auto" onchange="pageSizeChanged()"><option>25</option><option selected>50</option><option>100</option></select><button class="secondary" id="prevPage" onclick="changePage(-1)">← Previous</button><span id="pageInfo">Page 1 of 1</span><button class="secondary" id="nextPage" onclick="changePage(1)">Next →</button></div>
    </section>

    <section class="panel" id="detailPanel">
        <div class="status-line"><h2>Manual review detail</h2><span id="detailPosition" class="meta"></span></div>
        <div id="detailEmpty" class="empty">Select a table row to inspect and manually classify it.</div>
        <div id="detailContent" style="display:none">
            <div class="detail-grid">
                <div>
                    <dl id="detailMeta" class="detail-meta"></dl>
                    <h3>Source context</h3><pre id="detailContext"></pre>
                </div>
                <aside>
                    <h3>LLM reason</h3><div id="detailReason" class="reason"></div>
                    <h3 style="margin-top:13px">Manual verdict</h3>
                    <div class="actions"><button class="tp" onclick="saveManualVerdict('True Positive')">True Positive (T)</button><button class="fp" onclick="saveManualVerdict('False Positive')">False Positive (F)</button><button class="clear" onclick="saveManualVerdict('')">Clear</button></div>
                    <div class="actions" style="margin-top:9px"><button class="secondary" onclick="navigateDetail('previous')">← Previous</button><button class="secondary" onclick="navigateDetail('next')">Next →</button></div>
                    <div id="manualStatus" class="notice"></div>
                    <details style="margin-top:12px"><summary>Raw LLM response</summary><pre id="detailRaw"></pre></details>
                </aside>
            </div>
        </div>
    </section>

    <div id="folderModal" class="modal"><div class="modal-card"><div class="status-line"><strong>Choose target directory</strong><button class="secondary" onclick="closeBrowser()">Close</button></div><div id="browsePath" class="meta" style="margin-top:10px"></div><div id="folderList" class="folder-list"></div><button onclick="selectFolder()">Select this folder</button></div></div>

    <script>
        let activeJobId=null,eventCursor=0,currentBrowsePath='',currentPage=1,totalPages=1,selectedFindingId=null,reloadTimer=null;

        window.addEventListener('load',async()=>{await loadPatterns();await loadJobs();await pollStatus();setInterval(pollStatus,750);});

        async function loadPatterns(){const r=await fetch('/api/patterns'),d=await r.json(),list=document.getElementById('patternList');list.innerHTML='';d.patterns.forEach((p,i)=>{const row=document.createElement('label');row.className='pattern';const cb=document.createElement('input');cb.type='checkbox';cb.checked=true;cb.value=p;cb.id=`pattern-${i}`;cb.onchange=updatePatternCount;const text=document.createElement('span');text.textContent=p;row.append(cb,text);list.appendChild(row);});if(d.rejected.length)document.getElementById('patternNotice').textContent=`${d.rejected.length} noisy or invalid patterns automatically excluded.`;restoreSettings();updatePatternCount();}
        function selectedPatterns(){return Array.from(document.querySelectorAll('.pattern input:checked')).map(i=>i.value);}
        function updatePatternCount(){const all=document.querySelectorAll('.pattern input'),selected=document.querySelectorAll('.pattern input:checked');document.getElementById('patternCount').textContent=`${selected.length} included / ${all.length-selected.length} excluded`;}
        function filterPatterns(){const q=document.getElementById('patternSearch').value.toLowerCase();document.querySelectorAll('.pattern').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'flex':'none');}
        function toggleVisible(state){document.querySelectorAll('.pattern').forEach(r=>{if(r.style.display!=='none')r.querySelector('input').checked=state;});updatePatternCount();}
        function saveSettings(){localStorage.setItem('llmSastSettings',JSON.stringify({directory:value('directory'),model:value('model'),endpoint:value('endpoint'),maxItems:value('maxItems'),runLabel:value('runLabel'),temperature:value('temperature'),maxTokens:value('maxTokens'),timeout:value('timeout'),retries:value('retries'),patterns:selectedPatterns()}));}
        function restoreSettings(){let s;try{s=JSON.parse(localStorage.getItem('llmSastSettings'));}catch(_){return}if(!s)return;for(const [key,id] of Object.entries({directory:'directory',model:'model',endpoint:'endpoint',maxItems:'maxItems',runLabel:'runLabel',temperature:'temperature',maxTokens:'maxTokens',timeout:'timeout',retries:'retries'}))if(s[key]!==undefined)document.getElementById(id).value=s[key];if(Array.isArray(s.patterns)){const chosen=new Set(s.patterns);document.querySelectorAll('.pattern input').forEach(i=>i.checked=chosen.has(i.value));}}
        function value(id){return document.getElementById(id).value;}

        async function startScan(){const max=value('maxItems').trim();const payload={directory:value('directory').trim(),patterns:selectedPatterns(),endpoint:value('endpoint').trim(),model:value('model').trim(),run_label:value('runLabel').trim(),max_items:max?Number(max):null,temperature:Number(value('temperature')),max_tokens:Number(value('maxTokens')),timeout:Number(value('timeout')),retries:Number(value('retries'))};saveSettings();const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}),d=await r.json();if(!r.ok){showError(d.error||'Unable to start');return}activeJobId=d.job_id;eventCursor=0;currentPage=1;selectedFindingId=null;showError('');await loadJobs();ensureJobOption(activeJobId,'Active scan');document.getElementById('jobSelect').value=activeJobId;await loadResults();await pollStatus();}
        async function pauseScan(){const r=await fetch('/api/scan/pause',{method:'POST'}),d=await r.json();if(!r.ok)showError(d.error);await pollStatus();}
        async function pollStatus(){try{const r=await fetch(`/api/scan/status?after=${eventCursor}`),d=await r.json();d.events.forEach(handleEvent);eventCursor=d.event_sequence;renderStatus(d);if(d.job_id)ensureJobOption(d.job_id,'Active scan');}catch(e){showError(`Status error: ${e}`);}}
        function handleEvent(e){if(e.type==='reviewing'){const f=e.data;document.getElementById('currentMeta').textContent=`${f.filepath}:${f.line_num} — ${f.pattern}`;document.getElementById('currentContext').textContent=f.context.map(l=>`${l.is_target?'>>':'  '} ${String(l.line_num).padStart(6)} | ${l.text}`).join('\\n');}else if(e.type==='result'){if(activeJobId===e.data.job_id){loadResults(false);loadJobs();}}else if(e.type==='retry'){showError(`Attempt ${e.data.attempt}/${e.data.total_attempts} failed; retrying in ${e.data.delay}s: ${e.data.error}`);}else if(e.type==='error')showError(e.data.message);}
        function renderStatus(d){document.getElementById('status').textContent=d.status;document.getElementById('jobId').textContent=d.job_id?`Active job ${d.job_id.slice(0,12)}`:'';const s=d.stats||{};document.getElementById('liveSummary').textContent=`${d.reviewed||0} newly reviewed · ${d.resumed||0} resumed/skipped · ${s.matches_found||0} matches · ${s.scanned_files||0} files scanned · ${s.skipped_files||0} skipped · ${(s.errors||[]).length} errors`;if(d.error)showError(d.error);const running=d.status==='running'||d.status==='pause_requested';document.getElementById('startButton').disabled=running;document.getElementById('pauseButton').disabled=!running;}

        async function loadJobs(){const r=await fetch('/api/jobs'),d=await r.json();if(!r.ok){showError(d.error);return}const select=document.getElementById('jobSelect'),keep=activeJobId||select.value;select.innerHTML='<option value="">Choose a saved job</option>';d.jobs.forEach(j=>{const o=document.createElement('option');o.value=j.job_id;o.textContent=`${j.run_label||'(no label)'} — ${j.count} findings — ${j.target_directory}`;o.dataset.target=j.target_directory;select.appendChild(o);});if(keep){ensureJobOption(keep,'Active scan');select.value=keep;activeJobId=keep;}else if(d.jobs.length){activeJobId=d.jobs[0].job_id;select.value=activeJobId;}updateJobTarget();if(activeJobId)await loadResults();}
        function ensureJobOption(id,label){const s=document.getElementById('jobSelect');if(!Array.from(s.options).some(o=>o.value===id)){const o=document.createElement('option');o.value=id;o.textContent=`${label} — ${id.slice(0,12)}`;s.appendChild(o);}}
        function changeJob(){activeJobId=value('jobSelect')||null;currentPage=1;selectedFindingId=null;clearDetail();updateJobTarget();loadResults();}
        function updateJobTarget(){const o=document.getElementById('jobSelect').selectedOptions[0];document.getElementById('jobTarget').value=o?.dataset.target||'';}

        function filterOptions(){return{query:value('resultQuery'),llm_verdict:value('llmFilter'),manual_verdict:value('manualFilter'),pattern:value('resultPattern'),confidence_min:value('confidenceMin'),confidence_max:value('confidenceMax'),sort:value('sort'),direction:value('direction')};}
        function resultParams(includePage=true){const p=new URLSearchParams({job_id:activeJobId||'',...filterOptions()});if(includePage){p.set('page',currentPage);p.set('page_size',value('pageSize'));}return p;}
        function scheduleResultsReload(){clearTimeout(reloadTimer);reloadTimer=setTimeout(()=>{currentPage=1;loadResults();},250);}
        function filtersChanged(){currentPage=1;loadResults();}
        function pageSizeChanged(){currentPage=1;loadResults();}
        function changePage(delta){currentPage=Math.max(1,Math.min(totalPages,currentPage+delta));loadResults();}
        async function loadResults(){if(!activeJobId){renderEmptyTable('Choose a saved job or start a scan.');renderStats(null);return}const r=await fetch(`/api/results?${resultParams()}`),d=await r.json();if(!r.ok){showError(d.error);return}currentPage=d.pagination.page;totalPages=d.pagination.total_pages;renderTable(d.results);renderStats(d.summary);document.getElementById('pageInfo').textContent=`Page ${currentPage} of ${totalPages} · ${d.pagination.total_filtered} filtered`;document.getElementById('prevPage').disabled=currentPage<=1;document.getElementById('nextPage').disabled=currentPage>=totalPages;}
        function renderTable(rows){const body=document.getElementById('resultBody');body.innerHTML='';if(!rows.length){renderEmptyTable('No findings match the current filters.');return}rows.forEach(row=>{const tr=document.createElement('tr');tr.dataset.findingId=row['Finding ID'];if(row['Finding ID']===selectedFindingId)tr.className='selected';const values=[row['Serial Number'],row['Matched Pattern'],row['File Name'],row['Line Number']];values.forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===2)td.title=row['Filename'];tr.appendChild(td);});tr.appendChild(verdictCell(row['Verdict']));tr.appendChild(verdictCell(row['Manual Verdict']||'Unreviewed'));const reason=document.createElement('td');reason.textContent=row['Reason'];reason.title=row['Reason'];tr.appendChild(reason);const confidence=document.createElement('td');confidence.textContent=formatConfidence(row['Confidence']);tr.appendChild(confidence);tr.onclick=()=>selectFinding(row['Finding ID']);body.appendChild(tr);});}
        function verdictCell(v){const td=document.createElement('td'),b=document.createElement('span');b.className=`badge ${v==='True Positive'?'tp':v==='False Positive'?'fp':'pending'}`;b.textContent=v;td.appendChild(b);return td;}
        function renderEmptyTable(message){document.getElementById('resultBody').innerHTML='';const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=8;td.className='empty';td.textContent=message;tr.appendChild(td);document.getElementById('resultBody').appendChild(tr);}
        function renderStats(s){const box=document.getElementById('stats');if(!s){box.innerHTML='';return}const items=[['Total',s.total],['LLM TP',s.llm_true_positive],['LLM FP',s.llm_false_positive],['Manual TP',s.manual_true_positive],['Manual FP',s.manual_false_positive],['Unreviewed',s.manual_unreviewed],['Agreement',s.agreement],['Disagreement',s.disagreement],['Avg. confidence',s.average_confidence==null?'—':`${(s.average_confidence*100).toFixed(1)}%`]];box.innerHTML='';items.forEach(([label,v])=>{const card=document.createElement('div');card.className='stat';const strong=document.createElement('strong');strong.textContent=v;const span=document.createElement('span');span.textContent=label;card.append(strong,span);box.appendChild(card);});}
        function formatConfidence(v){const n=Number(v);return Number.isFinite(n)?`${(n*100).toFixed(1)}%`:v;}

        async function selectFinding(id){if(!activeJobId||!id)return;const r=await fetch(`/api/results/${encodeURIComponent(activeJobId)}/${encodeURIComponent(id)}`),d=await r.json();if(!r.ok){showError(d.error);return}selectedFindingId=id;renderDetail(d.result);document.querySelectorAll('#resultBody tr').forEach(tr=>tr.classList.toggle('selected',tr.dataset.findingId===id));}
        function renderDetail(row){document.getElementById('detailEmpty').style.display='none';document.getElementById('detailContent').style.display='block';document.getElementById('detailPosition').textContent=`Finding ${row['Serial Number']}`;const pairs=[['Pattern',row['Matched Pattern']],['File',row['Filename']],['Line',row['Line Number']],['Matched line',row['Matched Line']],['LLM verdict',row['Verdict']],['Confidence',formatConfidence(row['Confidence'])],['Manual verdict',row['Manual Verdict']||'Unreviewed'],['Model',row['Model']],['LLM reviewed',row['Reviewed At']],['Manual reviewed',row['Manual Reviewed At']||'—']];const dl=document.getElementById('detailMeta');dl.innerHTML='';pairs.forEach(([k,v])=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=k;dd.textContent=v;dl.append(dt,dd);});document.getElementById('detailContext').textContent=row['Context'];document.getElementById('detailReason').textContent=row['Reason'];document.getElementById('detailRaw').textContent=row['Raw Response'];document.getElementById('manualStatus').textContent=row['Manual Verdict']?`Saved manual verdict: ${row['Manual Verdict']}`:'Not manually reviewed';}
        function clearDetail(){selectedFindingId=null;document.getElementById('detailEmpty').style.display='block';document.getElementById('detailContent').style.display='none';}
        async function saveManualVerdict(verdict){if(!selectedFindingId)return;const r=await fetch('/api/results/manual-verdict',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:activeJobId,finding_id:selectedFindingId,verdict,filters:filterOptions()})}),d=await r.json();if(!r.ok){showError(d.error);return}document.getElementById('manualStatus').textContent=verdict?`Saved manual verdict: ${verdict}`:'Manual verdict cleared';await loadResults();if(verdict&&d.next_unreviewed_finding_id)await selectFinding(d.next_unreviewed_finding_id);else await selectFinding(selectedFindingId);}
        async function navigateDetail(move){if(!selectedFindingId)return;const p=resultParams(false);p.set('finding_id',selectedFindingId);p.set('move',move);const r=await fetch(`/api/results/navigate?${p}`),d=await r.json();if(d.finding_id)await selectFinding(d.finding_id);else document.getElementById('manualStatus').textContent=`No ${move} finding under the current filters.`;}
        document.addEventListener('keydown',e=>{if(['INPUT','SELECT','TEXTAREA'].includes(e.target.tagName)||!selectedFindingId)return;if(e.key.toLowerCase()==='t')saveManualVerdict('True Positive');else if(e.key.toLowerCase()==='f')saveManualVerdict('False Positive');else if(e.key==='ArrowRight')navigateDetail('next');else if(e.key==='ArrowLeft')navigateDetail('previous');});

        function showError(message){document.getElementById('error').textContent=message||'';}
        async function openBrowser(){document.getElementById('folderModal').classList.add('open');await loadFolders(value('directory').trim());}
        function closeBrowser(){document.getElementById('folderModal').classList.remove('open');}
        async function loadFolders(path){const r=await fetch(`/api/browse?path=${encodeURIComponent(path||'')}`),d=await r.json();if(!r.ok){showError(d.error);return}currentBrowsePath=d.current_path;document.getElementById('browsePath').textContent=currentBrowsePath;const list=document.getElementById('folderList');list.innerHTML='';if(d.parent_path!==d.current_path)addFolder(list,'..',d.parent_path);d.subdirs.forEach(name=>addFolder(list,name,currentBrowsePath==='/'?`/${name}`:`${currentBrowsePath}/${name}`));}
        function addFolder(list,name,path){const row=document.createElement('div');row.className='folder';row.textContent=`📁 ${name}`;row.onclick=()=>loadFolders(path);list.appendChild(row);}
        function selectFolder(){document.getElementById('directory').value=currentBrowsePath;closeBrowser();}
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/patterns")
def patterns():
    accepted, rejected = load_patterns(WEB_PATTERNS_FILE)
    return jsonify({"patterns": accepted, "rejected": rejected})


@app.route("/api/browse")
def browse():
    path = request.args.get("path", "").strip() or os.getcwd()
    try:
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            path = os.getcwd()
        parent = os.path.dirname(path)
        subdirs = [
            item
            for item in sorted(os.listdir(path))
            if item not in IGNORE_DIRS and os.path.isdir(os.path.join(path, item))
        ]
        return jsonify({
            "current_path": path,
            "parent_path": parent,
            "subdirs": subdirs,
        })
    except OSError as exc:
        return jsonify({"error": str(exc)}), 400


def parse_scan_request(data):
    target_dir = os.path.realpath(os.path.abspath(str(data.get("directory", ""))))
    if not os.path.isdir(target_dir):
        raise ValueError("Directory not found or is not a directory")

    accepted, _ = load_patterns(WEB_PATTERNS_FILE)
    requested_patterns = data.get("patterns")
    if not isinstance(requested_patterns, list):
        raise ValueError("Patterns must be a list")
    requested_set = {
        pattern for pattern in requested_patterns if isinstance(pattern, str)
    }
    selected_patterns = [
        pattern for pattern in accepted if pattern in requested_set
    ]
    if not selected_patterns:
        raise ValueError("Select at least one pattern")

    endpoint = str(data.get("endpoint", "")).strip()
    model = str(data.get("model", "")).strip()
    if not endpoint or not model:
        raise ValueError("Endpoint and model are required")

    max_items = data.get("max_items")
    if max_items in ("", None):
        max_items = None
    else:
        max_items = int(max_items)
        if max_items <= 0:
            raise ValueError("Max items must be greater than zero")

    temperature = float(data.get("temperature", 0.2))
    max_tokens = int(data.get("max_tokens", 500))
    timeout = float(data.get("timeout", 120))
    retries = int(data.get("retries", 3))
    if not 0.0 <= temperature <= 2.0:
        raise ValueError("Temperature must be between 0 and 2")
    if max_tokens <= 0 or timeout <= 0 or retries < 0:
        raise ValueError("Max tokens and timeout must be positive; retries cannot be negative")

    args = SimpleNamespace(
        endpoint=endpoint,
        model=model,
        max_items=max_items,
        run_label=str(data.get("run_label", "")).strip(),
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        retries=retries,
        output=WEB_RESULTS_FILE,
    )
    return target_dir, selected_patterns, args


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    with STATE_LOCK:
        thread = web_state["thread"]
        if thread is not None and thread.is_alive():
            return jsonify({"error": "A scan is already running"}), 409

    try:
        target_dir, selected_patterns, args = parse_scan_request(
            request.get_json(silent=True) or {}
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    with RESULTS_LOCK:
        try:
            existing_rows, repaired = llm.initialize_results(WEB_RESULTS_FILE)
        except (llm.LLMReviewError, OSError) as exc:
            return jsonify({"error": str(exc)}), 400

    job_id = llm.build_job_id(target_dir, selected_patterns, args)
    token = uuid.uuid4().hex
    stop_event = threading.Event()
    worker = threading.Thread(
        target=run_web_scan,
        args=(
            token,
            stop_event,
            target_dir,
            selected_patterns,
            args,
            existing_rows,
        ),
        daemon=True,
        name=f"llm-scan-{job_id[:8]}",
    )
    with STATE_LOCK:
        web_state.update({
            "token": token,
            "thread": worker,
            "stop_event": stop_event,
            "status": "running",
            "job_id": job_id,
            "target_directory": target_dir,
            "reviewed": 0,
            "resumed": 0,
            "stats": new_scan_stats(),
            "error": (
                f"Repaired {repaired} invalid or duplicate CSV rows"
                if repaired else None
            ),
            "events": [],
            "event_sequence": 0,
        })
    worker.start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/api/scan/pause", methods=["POST"])
def pause_scan():
    with STATE_LOCK:
        thread = web_state["thread"]
        stop_event = web_state["stop_event"]
        if thread is None or not thread.is_alive() or stop_event is None:
            return jsonify({"error": "No scan is currently running"}), 409
        stop_event.set()
        web_state["status"] = "pause_requested"
    return jsonify({"status": "pause_requested"})


@app.route("/api/scan/status")
def scan_status():
    try:
        after = max(0, int(request.args.get("after", "0")))
    except ValueError:
        return jsonify({"error": "after must be an integer"}), 400
    return jsonify(public_state(after))


@app.route("/api/jobs")
def jobs():
    try:
        rows = load_result_rows()
    except (llm.LLMReviewError, OSError, csv.Error) as exc:
        return jsonify({"error": str(exc)}), 400

    jobs_by_id = {}
    for row in rows:
        job_id = row["Job ID"]
        if job_id not in jobs_by_id:
            jobs_by_id[job_id] = {
                "job_id": job_id,
                "run_label": row["Run Label"],
                "target_directory": row["Target Directory"],
                "model": row["Model"],
                "count": 0,
                "last_reviewed_at": row["Reviewed At"],
            }
        job = jobs_by_id[job_id]
        job["count"] += 1
        if row["Reviewed At"] > job["last_reviewed_at"]:
            job["last_reviewed_at"] = row["Reviewed At"]
    ordered = sorted(
        jobs_by_id.values(),
        key=lambda job: job["last_reviewed_at"],
        reverse=True,
    )
    return jsonify({"jobs": ordered})


@app.route("/api/results")
def results():
    job_id = request.args.get("job_id", "").strip()
    if not job_id:
        return jsonify({"error": "job_id is required"}), 400
    try:
        page = max(1, int(request.args.get("page", "1")))
        requested_page_size = int(request.args.get("page_size", "50"))
    except ValueError:
        return jsonify({"error": "page and page_size must be integers"}), 400
    page_size = requested_page_size if requested_page_size in {25, 50, 100} else 50

    try:
        all_rows = load_result_rows()
    except (llm.LLMReviewError, OSError, csv.Error) as exc:
        return jsonify({"error": str(exc)}), 400
    job_rows = numbered_job_rows(all_rows, job_id)
    filtered = filter_and_sort_rows(job_rows, request.args)
    total_pages = max(1, (len(filtered) + page_size - 1) // page_size)
    page = min(page, total_pages)
    start = (page - 1) * page_size
    page_rows = filtered[start:start + page_size]
    return jsonify({
        "results": [lightweight_result(row) for row in page_rows],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_filtered": len(filtered),
            "total_pages": total_pages,
        },
        "summary": result_summary(job_rows),
    })


@app.route("/api/results/<job_id>/<finding_id>")
def result_detail(job_id, finding_id):
    try:
        rows = load_result_rows()
    except (llm.LLMReviewError, OSError, csv.Error) as exc:
        return jsonify({"error": str(exc)}), 400
    row = find_result(rows, job_id, finding_id)
    if row is None:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify({"result": row})


@app.route("/api/results/manual-verdict", methods=["POST"])
def manual_verdict():
    data = request.get_json(silent=True) or {}
    job_id = str(data.get("job_id", "")).strip()
    finding_id = str(data.get("finding_id", "")).strip()
    verdict = str(data.get("verdict", "")).strip()
    if not job_id or not finding_id:
        return jsonify({"error": "job_id and finding_id are required"}), 400
    if verdict not in llm.VALID_VERDICTS | {""}:
        return jsonify({"error": "Invalid manual verdict"}), 400

    try:
        with RESULTS_LOCK:
            rows, _ = llm.initialize_results(WEB_RESULTS_FILE)
            numbered = numbered_job_rows(rows, job_id)
            current = next(
                (row for row in numbered if row["Finding ID"] == finding_id),
                None,
            )
            if current is None:
                return jsonify({"error": "Finding not found"}), 404

            navigation_options = data.get("filters") or {}
            ordered_before_update = filter_and_sort_rows(
                numbered,
                navigation_options,
            )
            current_index = next(
                (
                    index for index, row in enumerate(ordered_before_update)
                    if row["Finding ID"] == finding_id
                ),
                -1,
            )
            next_unreviewed = None
            if current_index >= 0:
                for candidate in ordered_before_update[current_index + 1:]:
                    if not candidate.get("Manual Verdict"):
                        next_unreviewed = candidate["Finding ID"]
                        break

            for row in rows:
                if row["Job ID"] == job_id and row["Finding ID"] == finding_id:
                    row["Manual Verdict"] = verdict
                    row["Manual Reviewed At"] = (
                        datetime.now(timezone.utc).isoformat() if verdict else ""
                    )
                    updated = row
                    break
            llm.write_rows_atomically(WEB_RESULTS_FILE, rows)
    except (llm.LLMReviewError, OSError, csv.Error) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "status": "saved",
        "result": updated,
        "next_unreviewed_finding_id": next_unreviewed,
    })


@app.route("/api/results/navigate")
def navigate_results():
    job_id = request.args.get("job_id", "").strip()
    finding_id = request.args.get("finding_id", "").strip()
    direction = request.args.get("move", "next")
    unreviewed_only = request.args.get("unreviewed", "0") == "1"
    if not job_id or not finding_id:
        return jsonify({"error": "job_id and finding_id are required"}), 400
    if direction not in {"next", "previous"}:
        return jsonify({"error": "move must be next or previous"}), 400
    try:
        rows = load_result_rows()
    except (llm.LLMReviewError, OSError, csv.Error) as exc:
        return jsonify({"error": str(exc)}), 400
    ordered = filter_and_sort_rows(numbered_job_rows(rows, job_id), request.args)
    index = next(
        (i for i, row in enumerate(ordered) if row["Finding ID"] == finding_id),
        -1,
    )
    if index < 0:
        return jsonify({"finding_id": None})
    candidates = ordered[index + 1:] if direction == "next" else reversed(ordered[:index])
    for candidate in candidates:
        if not unreviewed_only or not candidate.get("Manual Verdict"):
            return jsonify({"finding_id": candidate["Finding ID"]})
    return jsonify({"finding_id": None})


if __name__ == "__main__":
    print("Starting src-triage on LAN at http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
