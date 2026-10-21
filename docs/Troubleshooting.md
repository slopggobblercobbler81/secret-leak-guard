# 🔧 Troubleshooting & FAQ

Common solutions and configuration tips for **Secret Leak Guard**.

---

## ❓ Frequently Encountered Issues

### 1. False Positives on Test Data & Mock Secrets

**Symptom**: Dummy credentials in test suites (e.g. `tests/fixtures/mock_keys.py`) trigger security alerts.

**Solution**:
1. Use `.secretleakguardignore` to exclude testing fixture directories:
   ```text
   # .secretleakguardignore
   tests/fixtures/*
   *.sample.env
   node_modules/
   ```
2. Or use inline comment suppression:
   ```python
   MOCK_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # secret-leak-guard: ignore
   ```

---

### 2. Tuning Entropy Thresholds

**Symptom**: Cryptographic salts, mock hashes, or long UUIDs are triggering entropy warnings.

**Solution**:
Increase the entropy sensitivity threshold (default is typically $4.3$ bits/character):
```bash
secret-leak-guard scan . --entropy-threshold 4.8
```
A higher value requires denser randomness before flagging a token.

---

### 3. Pre-Commit Hook Skipped or Permission Denied

**Symptom**: `git commit` fails with `permission denied: .git/hooks/pre-commit` on Linux/macOS.

**Solution**:
Ensure executable permissions are granted:
```bash
chmod +x .git/hooks/pre-commit
```

If you intentionally need to bypass the hook for an emergency hotfix:
```bash
git commit -m "Emergency fix" --no-verify
```

---

### 4. Git Diff Error in Shallow Clones (CI)

**Symptom**: In GitHub Actions or CI environments, running `secret-leak-guard diff` fails with:
`fatal: ambiguous argument 'HEAD~1': unknown revision or path not in the working tree`

**Solution**:
Shallow checkouts (`fetch-depth: 1`) omit commit history. Configure `actions/checkout` with full history or fetch the target branch:
```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```
Or run `secret-leak-guard scan .` across the repository workspace instead of diffing against a non-existent parent commit.

---

## 📞 Reporting Issues & Contributing

If you encounter an unhandled exception or reproducible bug, please file an issue on GitHub:
👉 [https://github.com/slopggobblercobbler81/secret-leak-guard/issues](https://github.com/slopggobblercobbler81/secret-leak-guard/issues)
