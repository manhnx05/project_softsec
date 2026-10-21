# Fuzzing Security Report: C buffer_copy (vulnerable)
**Mode**: Whitebox (ASan / Coverage-Guided Memory Auditing)  
**Total Executions**: 20  
**Coverage**: 66.67%  
**Unique Crashes**: 1  
**Hangs / Timeouts**: 0  
**Execution Duration**: 2.20s  

## 1. Discovered Crashes & Memory Violations
| Error Type | Exit Code | Payload (Hex) | Minimised Payload | Sanitizer? |
| :--- | :--- | :--- | :--- | :--- |
| **Segmentation Fault / Access Violation** | 3221225477 | `2d31...` | `b'-'` | False |

```text
Process crashed with exit code 3221225477
```


## 2. Remediation Suggestions
1. Enforce strict lower and upper bounds checks: `if (length < 0 || length > dest_capacity) return ERROR;`
2. Replace unrestricted `memcpy` with length-bounded `safe_buffer_copy` and verify null-termination `dest[size-1] = '\0'`
3. Validate unsigned type casting to prevent signed negative conversion (`int` to `size_t` wrapping)
4. Compile with `-fsanitize=address,undefined` in continuous integration to prevent silent heap/stack corruptions