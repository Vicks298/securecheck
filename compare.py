"""Compare two scan files: python3 compare.py before.json after.json"""
import json
import sys

ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def load(path):
    with open(path) as fh:
        d = json.load(fh)
    items = {(f["check"], f["title"]): f["severity"] for f in d["findings"] if f["severity"] != "Info"}
    return d, items


def compare(before_path, after_path):
    b, bi = load(before_path)
    a, ai = load(after_path)
    fixed = sorted((k for k in bi if k not in ai), key=lambda k: ORDER[bi[k]])
    still = sorted((k for k in bi if k in ai), key=lambda k: ORDER[ai[k]])
    new = sorted((k for k in ai if k not in bi), key=lambda k: ORDER[ai[k]])
    lines = [f"Domain: {a['domain']}", f"Before: {b['date'][:10]}   After: {a['date'][:10]}",
             f"Problems: {len(bi)} before -> {len(ai)} after", ""]
    for name, group, src in (("Fixed", fixed, bi), ("Still open", still, ai), ("New since the first scan", new, ai)):
        lines.append(f"{name} ({len(group)})")
        lines += [f"  [{src[k]}] {k[1]}" for k in group] or ["  none"]
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    print(compare(sys.argv[1], sys.argv[2]))
