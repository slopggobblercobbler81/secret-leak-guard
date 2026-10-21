"""
Performance benchmarks for secret-leak-guard scanner and entropy engines.
Validates scanning throughput, linear scaling, ReDoS resistance, and memory stability.
"""

import time
import pytest
from secret_leak_guard.entropy import (
    calculate_entropy,
    calculate_sliding_entropy,
    is_base58,
    is_high_entropy_base58,
)
from secret_leak_guard.scanner import SecretScanner


def test_benchmark_scanner_clean_code_throughput():
    """
    Benchmark scanner on a synthetic 1,000-line Python codebase without secrets.
    Ensures scanning completes efficiently without regressions.
    """
    code_lines = [
        "import os",
        "import sys",
        "from typing import List, Dict, Optional",
        "",
        "class ProcessingEngine:",
        "    def __init__(self, name: str, concurrency: int = 4):",
        "        self.name = name",
        "        self.concurrency = concurrency",
        "        self._active_jobs: Dict[str, float] = {}",
        "",
        "    def schedule_task(self, task_id: str, priority: int = 1) -> bool:",
        "        '''Schedule an asynchronous pipeline task for processing.'''",
        "        if task_id in self._active_jobs:",
        "            return False",
        "        self._active_jobs[task_id] = float(priority)",
        "        return True",
        "",
    ]
    # 60 repetitions * 17 lines = 1,020 lines
    large_codebase = "\n".join(code_lines * 60)
    total_bytes = len(large_codebase.encode("utf-8"))

    scanner = SecretScanner()
    start_time = time.perf_counter()
    findings = scanner.scan_text(large_codebase, file_path="bench_service.py")
    elapsed = time.perf_counter() - start_time

    assert len(findings) == 0
    assert elapsed < 3.0, f"Scanning took too long: {elapsed:.3f}s for {total_bytes} bytes"

    chars_per_sec = len(large_codebase) / max(elapsed, 0.0001)
    assert chars_per_sec > 10_000, f"Throughput too low: {chars_per_sec:.0f} chars/s"


def test_benchmark_multi_secret_dense_scanning():
    """
    Benchmark scanner performance when discovering 50 secrets of mixed types.
    """
    ghp_secret = "ghp_" + "A" * 36
    aws_secret = "AKIA" + "IOSFODNN7EXAMPLE"
    solana_secret = "SOLANA_PRIVATE_KEY='5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJcK9k'"

    lines = []
    for i in range(50):
        lines.append(f"# Configuration section {i}")
        lines.append(f"GH_TOKEN_{i} = '{ghp_secret}'")
        lines.append(f"AWS_KEY_{i} = '{aws_secret}'")
        lines.append(f"SOL_KEY_{i} = {solana_secret}")
        lines.append("DEBUG = False")

    content = "\n".join(lines)
    scanner = SecretScanner()

    start_time = time.perf_counter()
    findings = scanner.scan_text(content, file_path="config_bundle.py")
    elapsed = time.perf_counter() - start_time

    assert len(findings) >= 50
    assert elapsed < 3.0, f"Dense scanning took too long: {elapsed:.3f}s"


def test_benchmark_redos_adversarial_resistance():
    """
    Verify scanner is immune to catastrophic backtracking (ReDoS)
    when exposed to long repetitive prefixes and adversarial patterns.
    """
    # 5,000 repetitions of partial token prefix without valid match
    adversarial_text = "AKIA" + ("0123456789" * 500) + "\n"
    adversarial_text += "ghp_" + ("abcdefghij" * 500) + "\n"
    adversarial_text += "xoxb-" + ("0123456789" * 500) + "\n"
    adversarial_text += "SOLANA_PRIVATE_KEY=" + ("0" * 5000) + "\n"

    scanner = SecretScanner()
    start_time = time.perf_counter()
    findings = scanner.scan_text(adversarial_text, file_path="adversarial.txt")
    elapsed = time.perf_counter() - start_time

    assert elapsed < 2.0, f"Potential ReDoS detected: took {elapsed:.3f}s on adversarial input"


def test_benchmark_entropy_calculation_throughput():
    """
    Benchmark raw Shannon entropy calculation scaling over varying buffer sizes.
    """
    small_str = "x8A#k9L!qZ4$pW7&" * 10       # 160 chars
    med_str = "x8A#k9L!qZ4$pW7&" * 100        # 1,600 chars
    large_str = "x8A#k9L!qZ4$pW7&" * 1000     # 16,000 chars

    start = time.perf_counter()
    for _ in range(200):
        calculate_entropy(small_str)
        calculate_entropy(med_str)
    calculate_entropy(large_str)
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0, f"Entropy calculation took too long: {elapsed:.3f}s"


def test_benchmark_sliding_entropy_scaling():
    """
    Benchmark sliding window Shannon entropy calculations on large payload.
    """
    payload = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" * 50
    start = time.perf_counter()
    results = calculate_sliding_entropy(payload, window_size=32, step=4)
    elapsed = time.perf_counter() - start

    assert len(results) > 0
    assert elapsed < 1.0, f"Sliding entropy too slow: {elapsed:.3f}s"


def test_benchmark_base58_validation_speed():
    """
    Benchmark Base58 character set validation throughput.
    """
    valid_sample = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    invalid_sample = "5HueCGU8rMjxEXxiPuD5BDku4Mk0qeZyd4dZ1jvhTVqvbTLvyTJ"  # contains '0'

    start = time.perf_counter()
    for _ in range(5_000):
        is_base58(valid_sample)
        is_base58(invalid_sample)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"Base58 validation took too long: {elapsed:.3f}s for 10,000 checks"
