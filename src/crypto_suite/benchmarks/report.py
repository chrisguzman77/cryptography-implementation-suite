from __future__ import annotations

from crypto_suite.benchmarks.bench import bench_all


def to_markdown(results) -> str:
    lines = []
    lines.append("| Primitive | Avg Seconds/op | Notes |")
    lines.append("|---|---:|---|")
    for r in results:
        lines.append(f"| {r.name} | {r.seconds:.8f} | {r.notes} |")
    return "\n".join(lines) + "\n"


def main():
    results = bench_all()
    md = "# Benchmark Results\n\n" + to_markdown(results)
    print(md)
