# CVE-2026-31431 "Copy Fail" - Local Privilege Escalation
## Python 3.7+ совместимая версия (включая Astra Linux)

---

## Данная версия эксплойта

**Это форк, адаптированный для Python 3.7, 3.8, 3.9, 3.10, 3.11.**  
Оригинальные эксплойты требуют Python 3.12+ из-за использования `os.splice()`.

### Совместимость

| ОС / Платформа | Python версия | Статус |
|----------------|---------------|--------|
| **Astra Linux (Common Edition)** | 3.7.3 | ✅ Работает |
| **Astra Linux (Special Edition)** | 3.7.3 | ✅ Работает |
| Debian 10 (buster) | 3.7.3 | ✅ Работает |
| Debian 11 (bullseye) | 3.9.2 | ✅ Работает |
| Ubuntu 18.04 | 3.6.9 | ✅ Работает |
| Ubuntu 20.04 | 3.8.10 | ✅ Работает |
| Ubuntu 22.04 | 3.10.6 | ✅ Работает |
| RHEL 8 | 3.6.8 | ✅ Работает |
| RHEL 9 | 3.9.18 | ✅ Работает |

### Почему не работает оригинал?

```python
# ❌ Оригинальный эксплойт (только Python 3.12+)
os.splice(fd_in, fd_out, length, offset_src=offset)
# AttributeError: module 'os' has no attribute 'splice'
