import os
import re
from collections import deque


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATTERNS_FILE = os.path.join(BASE_DIR, "patterns.txt")

IGNORE_DIRS = {
    '.git', 'node_modules', 'bin', 'obj', 'venv', '.idea', '.vscode',
    'dist', 'build'
}
IGNORE_EXTS = {
    '.xlsx', '.xls', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.ico',
    '.zip', '.tar', '.gz', '.7z', '.rar',
    '.dll', '.exe', '.bin', '.so', '.class', '.pyc', '.pdb'
}

# These tokens are valid syntax but far too broad to be useful as standalone
# security findings. Three-character security terms such as AES and MD5 remain
# valid.
NOISY_LITERAL_PATTERNS = {'*', '+', '?', 'var', 'let', 'set', 'map'}


def split_pattern_line(line):
    parts = []
    current = []
    depth_curly = 0
    depth_square = 0
    depth_round = 0

    for char in line:
        if char == '{':
            depth_curly += 1
        elif char == '}':
            depth_curly -= 1
        elif char == '[':
            depth_square += 1
        elif char == ']':
            depth_square -= 1
        elif char == '(':
            depth_round += 1
        elif char == ')':
            depth_round -= 1

        if (
            char == ','
            and depth_curly == 0
            and depth_square == 0
            and depth_round == 0
        ):
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        parts.append("".join(current).strip())
    return parts


def is_regex_pattern(pattern):
    if re.search(r'\\[swdBSWD]', pattern):
        return True
    if '[' in pattern and ']' in pattern:
        return True
    if '(' in pattern and ')' in pattern:
        inside = re.findall(r'\(([^)]+)\)', pattern)
        for content in inside:
            if any(c in content for c in ['+', '*', '?', '|', '\\', '{', '}']):
                return True
    if '|' in pattern:
        return True
    if pattern.startswith('^') or pattern.endswith('$'):
        return True
    if '.*' in pattern or '.+' in pattern:
        return True
    if re.search(r'\{\d+,?\d*\}', pattern):
        return True
    return False


def pattern_quality_issue(pattern):
    if pattern.strip().lower() in NOISY_LITERAL_PATTERNS:
        return "too broad as a standalone pattern"
    if is_regex_pattern(pattern):
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            if compiled.search('') is not None:
                return "regular expression can match an empty string"
        except re.error as exc:
            return f"invalid regular expression: {exc}"
    return None


def load_patterns(pattern_file=PATTERNS_FILE):
    patterns = []
    rejected = []
    if not os.path.exists(pattern_file):
        return patterns, rejected

    with open(pattern_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line == "#ERROR!" or line.startswith("Input decoding"):
                continue

            for pattern in split_pattern_line(line):
                issue = pattern_quality_issue(pattern)
                if issue:
                    rejected.append({
                        'pattern': pattern,
                        'line': line_number,
                        'reason': issue
                    })
                    continue
                try:
                    if is_regex_pattern(pattern):
                        re.compile(pattern, re.IGNORECASE)
                    else:
                        re.compile(re.escape(pattern), re.IGNORECASE)
                    if pattern not in patterns:
                        patterns.append(pattern)
                except re.error as exc:
                    rejected.append({
                        'pattern': pattern,
                        'line': line_number,
                        'reason': f"invalid regular expression: {exc}"
                    })
    return patterns, rejected


def get_all_patterns(pattern_file=PATTERNS_FILE):
    return load_patterns(pattern_file)[0]


def new_scan_stats():
    return {
        'scanned_files': 0,
        'skipped_files': 0,
        'matches_found': 0,
        'errors': []
    }


def compile_patterns(patterns):
    compiled_patterns = []
    for pattern in patterns:
        try:
            if is_regex_pattern(pattern):
                compiled = re.compile(pattern, re.IGNORECASE)
            else:
                compiled = re.compile(re.escape(pattern), re.IGNORECASE)
            compiled_patterns.append((pattern, compiled))
        except re.error:
            continue
    return compiled_patterns


def generate_matches(
    target_dir,
    selected_patterns,
    stats,
    all_matches_per_line=False,
    context_radius=8
):
    compiled_patterns = compile_patterns(selected_patterns)

    def record_walk_error(error):
        stats['errors'].append({
            'path': error.filename or target_dir,
            'reason': str(error)
        })

    for root, dirs, files in os.walk(target_dir, onerror=record_walk_error):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS)
        files.sort()
        for filename in files:
            if any(filename.lower().endswith(ext) for ext in IGNORE_EXTS):
                stats['skipped_files'] += 1
                continue

            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    stats['scanned_files'] += 1
                    previous_lines = deque(maxlen=context_radius)
                    pending = []

                    for line_num, line in enumerate(f, 1):
                        text = line.rstrip('\n\r')

                        completed = []
                        for finding in pending:
                            finding['context'].append({
                                'line_num': line_num,
                                'text': text,
                                'is_target': False
                            })
                            finding['following_lines'] += 1
                            if finding['following_lines'] == context_radius:
                                completed.append(finding)
                        for finding in completed:
                            pending.remove(finding)
                            finding.pop('following_lines', None)
                            stats['matches_found'] += 1
                            yield finding

                        matched_patterns = []
                        for raw_pattern, compiled_pattern in compiled_patterns:
                            if compiled_pattern.search(line):
                                matched_patterns.append(raw_pattern)
                                if not all_matches_per_line:
                                    break

                        for matched_pattern in matched_patterns:
                            context = [
                                {
                                    'line_num': prior_num,
                                    'text': prior_text,
                                    'is_target': False
                                }
                                for prior_num, prior_text in previous_lines
                            ]
                            context.append({
                                'line_num': line_num,
                                'text': text,
                                'is_target': True
                            })
                            pending.append({
                                'filepath': filepath,
                                'line_num': line_num,
                                'pattern': matched_pattern,
                                'context': context,
                                'following_lines': 0
                            })

                        previous_lines.append((line_num, text))

                    for finding in pending:
                        finding.pop('following_lines', None)
                        stats['matches_found'] += 1
                        yield finding
            except Exception as exc:
                stats['skipped_files'] += 1
                stats['errors'].append({
                    'path': filepath,
                    'reason': str(exc)
                })
