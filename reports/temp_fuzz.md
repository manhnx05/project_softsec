# Fuzzing Security Report: C buffer_copy (vulnerable)
**Mode**: Whitebox (Coverage-Guided + ASan Memory Auditing)  
**Total Executions**: 120  
**Coverage**: 91.67%  
**Unique Crashes**: 1  
**Hangs / Timeouts**: 0  
**Execution Speed**: 27.5 exec/s  
**Duration**: 4.36s  

## 1. Crashes & Memory Violations
| Error Type | Exit Code | Hex | Minimised | Sanitizer? |
| :--- | :--- | :--- | :--- | :--- |
| **Segmentation Fault / Access Violation** | 3221225477 | `2d31...` | `b'-1'` | False |

```
Exit 3221225477
```


## 2. Execution Trace
- `[Iter    1]` **NEW_BRANCH** | cov=16.7% | Unlocked: branch_format_spec, branch_large
- `[Iter    2]` **NEW_BRANCH** | cov=25.0% | Unlocked: branch_above_cap
- `[Iter    5]` **NEW_BRANCH** | cov=41.7% | Unlocked: branch_off_by_one_m1, branch_small
- `[Iter    7]` **NEW_BRANCH** | cov=50.0% | Unlocked: branch_negative_sign
- `[Iter    9]` **NEW_BRANCH** | cov=58.3% | Unlocked: branch_overflow_large
- `[Iter   11]` **NEW_BRANCH** | cov=66.7% | Unlocked: branch_null_byte
- `[Iter   43]` **NEW_BRANCH** | cov=75.0% | Unlocked: branch_all_zero
- `[Iter   89]` **NEW_BRANCH** | cov=83.3% | Unlocked: branch_exact_cap
- `[Iter   90]` **NEW_BRANCH** | cov=91.7% | Unlocked: branch_empty
- `[Iter  115]` **CRASH** | cov=91.7% | Segmentation Fault / Access Violation | ASan=False | saved to whitebox_crash_20261030_105222_020176.txt

## 3. Remediation Suggestions
1. Enforce strict bounds check: if (length < 0 || length > dest_capacity) return ERROR;
2. Replace memcpy with safe_buffer_copy that validates length before the copy operation
3. Validate signed->unsigned cast: only cast AFTER confirmed non-negative, non-overflowing check
4. Compile with -fsanitize=address,undefined in CI to detect silent heap/stack corruptions
5. Run CBMC bounded model checking: cbmc --unwind 32 --bounds-check copy_buffer.c