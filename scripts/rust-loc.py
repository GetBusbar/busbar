#!/usr/bin/env python3
"""Count Rust SOURCE lines: code only, no comments, no blank lines, tests separated.

Why this exists: `wc -l` over the tree answers 870,458, and that number is not a
measurement of anything. It counts doc comments (this repo writes a lot of them),
blank lines, and test code -- and in this tree test code is over half of some
crates. A plan sized against it is sized against fiction.

WHAT COUNTS AS A CODE LINE: a line carrying at least one non-whitespace character
that is not inside a comment. A line holding only `}` counts; a line holding only
`/// foo` does not. String contents count, because they are code.

The scanner is a real lexer, not a regex. It has to be: `let s = "// not a comment";`
and `r#"a "quote" inside"#` both defeat line-based stripping, and Rust block
comments NEST, which defeats the usual /* .. */ pairing.

TEST CLASSIFICATION, in order of precedence:
  1. path  -- anything under tests/, benches/, examples/, or named *_test(s).rs
  2. block -- a `#[cfg(test)]` / `#[cfg(any(test, ...))]` / `#[test]` attribute
              puts the item that follows it into the test bucket, tracked by brace
              depth so a nested `mod tests { .. }` ends where its braces end.
Everything else is production.
"""
import sys, os, json

def scan(src):
    """Return (code_line_flags, test_line_flags) as two sets of 1-indexed line numbers."""
    n = len(src)
    i = 0
    line = 1
    code_lines = set()
    # comment/string state
    block_depth = 0
    # test tracking: list of open (brace_depth_at_open) for test items
    test_lines = set()
    pending_test_attr = False   # saw #[cfg(test)] etc, awaiting the item
    test_stack = []             # brace depths at which a test item opened
    brace_depth = 0
    in_test = lambda: bool(test_stack)

    def mark(ln):
        code_lines.add(ln)
        if in_test() or pending_test_attr:
            test_lines.add(ln)

    while i < n:
        c = src[i]
        if c == '\n':
            line += 1; i += 1; continue
        if block_depth > 0:
            if src.startswith('/*', i): block_depth += 1; i += 2; continue
            if src.startswith('*/', i):
                block_depth -= 1; i += 2; continue
            i += 1; continue
        # line comment
        if src.startswith('//', i):
            while i < n and src[i] != '\n': i += 1
            continue
        # block comment
        if src.startswith('/*', i):
            block_depth = 1; i += 2; continue
        # raw string r"..." or r#*"..."#*
        if c == 'r' and i+1 < n and (src[i+1] == '"' or src[i+1] == '#'):
            j = i+1; hashes = 0
            while j < n and src[j] == '#': hashes += 1; j += 1
            if j < n and src[j] == '"':
                mark(line)
                j += 1
                close = '"' + '#'*hashes
                while j < n:
                    if src[j] == '\n': line += 1; mark(line); j += 1; continue
                    if src.startswith(close, j): j += len(close); break
                    j += 1
                i = j; continue
        # byte string b"..."
        if c == 'b' and i+1 < n and src[i+1] == '"':
            i += 1; c = '"'
        # normal string
        if c == '"':
            mark(line); i += 1
            while i < n:
                if src[i] == '\\': i += 2; continue
                if src[i] == '\n': line += 1; mark(line); i += 1; continue
                if src[i] == '"': i += 1; break
                i += 1
            continue
        # char literal or lifetime -- only treat as char if it closes on the same line
        if c == "'":
            j = i+1
            if j < n and src[j] == '\\':
                j += 2
                while j < n and src[j] != "'" and src[j] != '\n': j += 1
                if j < n and src[j] == "'": mark(line); i = j+1; continue
            elif j+1 < n and src[j+1] == "'":
                mark(line); i = j+2; continue
            mark(line); i += 1; continue   # lifetime
        if not c.isspace():
            # test attribute detection
            if c == '#':
                # read the attribute text to the matching ]
                j = i+1
                if j < n and src[j] == '!': j += 1
                if j < n and src[j] == '[':
                    depth = 0; k = j; 
                    while k < n:
                        if src[k] == '[': depth += 1
                        elif src[k] == ']':
                            depth -= 1
                            if depth == 0: break
                        k += 1
                    attr = src[j:k+1]
                    a = attr.replace(' ', '')
                    if 'cfg(test)' in a or 'cfg(any(test' in a or a.startswith('[test]') \
                       or 'cfg(all(test' in a or 'cfg_attr(test' in a:
                        pending_test_attr = True
            if c == '{':
                if pending_test_attr:
                    test_stack.append(brace_depth)
                    pending_test_attr = False
                brace_depth += 1
            elif c == '}':
                brace_depth -= 1
                if test_stack and brace_depth == test_stack[-1]:
                    mark(line)
                    test_stack.pop()
                    i += 1; continue
            elif c == ';' and pending_test_attr:
                pending_test_attr = False   # e.g. #[cfg(test)] mod tests;
            mark(line)
        i += 1
    return code_lines, test_lines

def is_test_path(p):
    parts = p.replace('\\', '/').split('/')
    if any(seg in ('tests', 'benches', 'examples', 'fuzz', 'testing') for seg in parts): return True
    b = parts[-1]
    return b.endswith('_test.rs') or b.endswith('_tests.rs') or b == 'test_support.rs'

def count_file(path):
    try:
        src = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        return 0, 0
    code, test = scan(src)
    if is_test_path(path):
        return 0, len(code)
    return len(code) - len(test), len(test)

def walk(root):
    if os.path.isfile(root):
        if root.endswith('.rs'):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('target', '.git')]
        for f in filenames:
            if f.endswith('.rs'):
                yield os.path.join(dirpath, f)

if __name__ == '__main__':
    roots = sys.argv[1:] or ['.']
    per = {}
    for root in roots:
        for p in walk(root):
            rel = os.path.relpath(p)
            parts = rel.split('/')
            crate = parts[1] if len(parts) > 1 and parts[0] == 'crates' else parts[0]
            prod, test = count_file(p)
            e = per.setdefault(crate, [0, 0, 0])
            e[0] += prod; e[1] += test; e[2] += 1
    rows = sorted(per.items(), key=lambda kv: -kv[1][0])
    tp = tt = tf = 0
    print(f"{'crate':<32}{'code':>10}{'test':>10}{'files':>8}")
    print('-'*60)
    for k, (p, t, f) in rows:
        if p or t:
            print(f"{k:<32}{p:>10,}{t:>10,}{f:>8}")
        tp += p; tt += t; tf += f
    print('-'*60)
    print(f"{'TOTAL':<32}{tp:>10,}{tt:>10,}{tf:>8}")
