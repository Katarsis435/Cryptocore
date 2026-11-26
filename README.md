# CryptoCore

CLI-инструмент для симметричной криптографии: AES-128 (ECB, CBC, CFB, OFB, CTR, GCM), хеширование (SHA-256, SHA3-256), HMAC и AEAD.

## Возможности

- **AES-128**: режимы `ecb`, `cbc`, `cfb`, `ofb`, `ctr`, `gcm`.
- **Аутентифицированное шифрование**: AES-GCM (с AAD) и Encrypt-then-MAC (библиотека).
- **Хеширование**: `sha256`, `sha3-256` (реализованы с нуля).
- **HMAC**: RFC 2104 поверх SHA-256 / SHA3-256, проверка через `--verify`.
- **Padding**: PKCS#7 для `ecb`/`cbc`; потоковые режимы работают без padding.
- **IV/Nonce**: 16 байт для CBC/CFB/OFB/CTR, 12 байт для GCM; генерируются автоматически.
- **Форматы файлов**:
  - `cbc`/`cfb`/`ofb`/`ctr`: `[16 байт IV][данные]`;
  - `gcm`: `[12 байт nonce][шифртекст][16 байт tag]`;
  - `ecb`: `[данные]` без IV.
- Работа с бинарными и текстовыми файлами, потоковая обработка больших файлов.

## Зависимости

- Python 3.12+
- `pycryptodome >= 3.20.0` (только AES-примитив)
- `openssl` в PATH (для тестов совместимости)

## Установка

```bash
git clone https://github.com/Katarsis435/Cryptocore.git
cd Cryptocore
python -m venv .venv
.venv\Scripts\activate               # Windows
pip install -r requirements.txt
pip install -e .
```

После `pip install -e .` команда `cryptocore` доступна в терминале.

## Шифрование и расшифрование

### Legacy-режимы (ECB, CBC, CFB, OFB, CTR)

Шифрование:
```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование (IV читается из первых 16 байт файла):
```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

IV вручную (hex, 32 символа = 16 байт):
```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 101112131415161718191a1b1c1d1e1f --input ciphertext.bin --output decrypted.txt
```

ECB не использует IV:
```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

### AES-GCM (AEAD)

Шифрование с AAD:
```bash
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input plaintext.txt --output ciphertext.bin
```

Расшифрование с правильным AAD:
```bash
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff \
  --input ciphertext.bin --output decrypted.txt
# OK: decrypted ... (exit 0)
```

Расшифрование с неверным AAD:
```bash
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad deadbeef \
  --input ciphertext.bin --output should_not_exist.txt
# [ERROR] Authentication failed: AAD mismatch or ciphertext tampered.
# exit 1, выходной файл не создаётся
```

Nonce вручную (12 байт, 24 hex-символа):
```bash
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --iv 000000000000000000000000 --input ciphertext.bin --output decrypted.txt
```

### Аргументы шифрования

| Аргумент | Описание |
|---|---|
| `--algorithm` | `aes`. |
| `--mode` | `ecb`, `cbc`, `cfb`, `ofb`, `ctr`, `gcm`. |
| `--encrypt` / `--decrypt` | Взаимоисключающие флаги. |
| `--key` | 32 hex-символа (16 байт). |
| `--iv` | IV (16 байт) или nonce (12 байт для GCM). Только при расшифровании. |
| `--aad` | Associated data в hex (только GCM). Необязателен. |
| `--input` | Путь к входному файлу. |
| `--output` | Путь к выходному файлу. |

## Хеширование (`dgst`)

Подкоманда `dgst` изолирована от шифрования.

```bash
cryptocore dgst --algorithm sha256 --input document.pdf
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
```

Формат вывода совместим с `sha256sum`:
```text
<hash_hex>  <file_path>
```

Алгоритмы:
- **SHA-256** — FIPS 180-4, Merkle–Damgård, 64 раунда.
- **SHA3-256** — FIPS 202, Keccak-f[1600], rate 1088 бит.

Оба читают файл по частям (8 КБ), память O(1), поддержка больших и пустых файлов.

## HMAC (`dgst --hmac`)

HMAC (RFC 2104) поверх SHA-256 / SHA3-256.

Генерация:
```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

Проверка по эталонному файлу:
```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected_hmac.txt
# [OK] HMAC verification successful (exit 0)
# [ERROR] HMAC verification failed (exit 1)
```

Запись в файл:
```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
```

Аргументы `dgst`:

| Аргумент | Описание |
|---|---|
| `--algorithm` | `sha256` или `sha3-256`. |
| `--input` | Файл или `-` для stdin. |
| `--output` | Записать `HASH  FILE` в файл. |
| `--hmac` | Включает режим HMAC (требует `--key`). |
| `--key` | HMAC-ключ в hex произвольной длины. |
| `--verify` | Сверить с ожидаемым HMAC из файла (exit 0/1). |

Формула HMAC:
```text
HMAC(K, m) = H( (K ⊕ opad) ‖ H( (K ⊕ ipad) ‖ m ) )
```
- Длинный ключ (`> 64 байт`) хешируется, короткий — zero-pad до 64 байт.
- Устойчив к length-extension, в отличие от `H(K ‖ m)`.
- Потоковая обработка файлов.

## AEAD: GCM и Encrypt-then-MAC

**AEAD** (Authenticated Encryption with Associated Data) одновременно обеспечивает конфиденциальность, целостность шифртекста и аутентификацию AAD. Расшифрование либо возвращает корректный plaintext, либо падает с ошибкой.

### AES-GCM

GCM = AES-CTR + GHASH (GF(2^128)), реализован с нуля по NIST SP 800-38D.

Формат:
```text
[12 байт nonce][шифртекст][16 байт tag]
```

Свойства:
- nonce генерируется через `os.urandom(12)` при каждом шифровании;
- tag проверяется **до** расшифрования (constant-time);
- при подмене AAD/шифртекста/tag → exit 1 и выходной файл не создаётся.

### Encrypt-then-MAC

Библиотечная реализация в `src/cryptocore/aead/etm.py`:

```text
C = E(Ke, P),   T = HMAC(Km, nonce ‖ C ‖ AAD),   output = nonce ‖ C ‖ T
```

- Шифрование: CTR.
- MAC: HMAC-SHA256.
- Ключи: `Ke = SHA256(K)[:16]`, `Km = SHA256(K)[16:]`.
- Проверка MAC до расшифрования.

### Почему GCM проверяет тег до расшифрования

Если расшифровать до проверки, злоумышленник может подсовывать модифицированные шифртексты и анализировать поведение (padding oracle, chosen-ciphertext, timing). GCM должен возвращать либо корректный plaintext, либо ошибку — без промежуточных состояний.

### Предупреждения по безопасности

- **Не переиспользуйте nonce** с тем же ключом: раскрывается XOR plaintext'ов и возможна подделка tag.
- **Неверный AAD = полный отказ**, а не «предупреждение».
- **Не игнорируйте exit code**: `1` означает, что данные изменены или ключ/AAD неверны.
- Для потоковых приложений со множеством сообщений используйте счётчик nonce или XChaCha20-Poly1305.

## Проверка совместимости с OpenSSL (legacy-режимы)

Автотесты (`tests/test_openssl.py`) проверяют ECB, CBC, CFB, OFB, CTR в обе стороны:
1. CryptoCore → OpenSSL: шифруем нашим, расшифровываем OpenSSL.
2. OpenSSL → CryptoCore: наоборот.
3. Побайтовое совпадение шифртекста.

Если `openssl` не в PATH, тесты скипаются.

Ручной пример для CBC:
```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cipher.bin
```

Извлечение IV (PowerShell):
```powershell
$data = [System.IO.File]::ReadAllBytes("cipher.bin")
[System.IO.File]::WriteAllBytes("ct_only.bin", $data[16..($data.Length - 1)])
$iv = -join ($data[0..15] | ForEach-Object { $_.ToString("x2") })
```

Расшифрование через OpenSSL:
```bash
openssl enc -aes-128-cbc -d -K 000102030405060708090a0b0c0d0e0f -iv $iv -in ct_only.bin -out decrypted.txt
```

Суффиксы OpenSSL для режимов:
- `cbc` → `-aes-128-cbc`
- `cfb` → `-aes-128-cfb`
- `ofb` → `-aes-128-ofb`
- `ctr` → `-aes-128-ctr`
- `ecb` → `-aes-128-ecb` (без IV)

> `openssl enc` **не поддерживает GCM**; совместимость GCM проверяется через NIST-векторы в `tests/test_gcm.py`.

## Тесты

```bash
python -m unittest discover -s tests -v
```

Состав:
- `tests/test_ecb.py` — ECB, PKCS#7, NIST-вектор.
- `tests/test_modes.py` — CBC, CFB, OFB, CTR, round-trip.
- `tests/test_openssl.py` — совместимость legacy-режимов с OpenSSL.
- `tests/test_hash.py` — SHA-256 / SHA3-256: NIST, hashlib, потоковость.
- `tests/test_hmac.py` — RFC 4231, verify, tamper, длины ключей.
- `tests/test_gcm.py` — NIST SP 800-38D (Test Cases 1–4), round-trip, tamper, nonce uniqueness.
- `tests/test_etm.py` — Encrypt-then-MAC round-trip и tamper.
- `tests/test_cli_dgst.py`, `tests/test_cli_gcm.py`, `tests/test_cli_keygen.py` — CLI.

## Обработка ошибок

- Неверный размер ключа (`--key 1234`) → exit ≠ 0.
- `--encrypt` и `--decrypt` одновременно → ошибка argparse.
- `--iv` при шифровании (legacy-режимы) → ошибка.
- `--iv` в ECB → ошибка.
- Входной файл короче IV при расшифровании → ошибка.
- Неверный AAD / подмена шифртекста в GCM → exit 1, выходной файл не создаётся.
- `--hmac` без `--key` → ошибка.

## Получение ключей из паролей (`derive`)

Спринт 7 добавляет подкоманду `derive` для получения ключей из паролей через **PBKDF2-HMAC-SHA256** (RFC 2898) и функцию иерархии ключей.

### Растяжение ключа (key stretching)

Пароли обычно имеют низкую энтропию, и простой хеш `SHA256(password)` подбирается перебором. **Key stretching** усложняет атаку:
- **Salt** — случайные 16 байт, уникальные для каждого пароля. Соль исключает радужные таблицы и одинаковые ключи для одинаковых паролей.
- **Iterations** — число повторных HMAC-вызовов (обычно 100 000–1 000 000). Каждая итерация удорожает перебор пропорционально.

### Использование

```bash
cryptocore derive --password "MyPass" --salt a1b2c3d4e5f601234567890123456789 --iterations 100000 --length 32
# 5f4dcc3b5aa765d61d8327deb882cf99...  a1b2c3d4e5f601234567890123456789
```

Без salt (генерируется случайно):
```bash
cryptocore derive --password "MyPass" --iterations 100000 --length 16
# 8d969eef6ecad3c29a3a629280e686cf...  e3b0c44298fc1c149afbf4c8996fb924
```

С сохранением в файл (сырые байты, не hex):
```bash
cryptocore derive --password "MyPass" --salt aabbccdd --iterations 100000 --length 32 --output app.key
```

### Аргументы `derive`

| Аргумент | Описание |
|---|---|
| `--password` | Пароль (строка). |
| `--salt` | Salt в hex. Если не указан — 16 случайных байт. |
| `--iterations` | Число итераций PBKDF2 (по умолчанию 100 000). |
| `--length` | Длина ключа в байтах (по умолчанию 32). |
| `--algorithm` | `pbkdf2` (пока единственный). |
| `--output` | Записать сырые байты ключа в файл. |

Формат stdout: `<KEY_HEX>  <SALT_HEX>`. Salt **в файл не пишется**, если не запрошен явно.

### Иерархия ключей (библиотека)

```python
from cryptocore.kdf import derive_key
master = b"0" * 32
enc_key = derive_key(master, "encryption", 32)
auth_key = derive_key(master, "authentication", 32)
# enc_key != auth_key, детерминированно для тех же входов
```

`derive_key` использует `HMAC(master_key, context || counter)` — детерминированная схема для получения подключей с уникальными контекстами.

### Безопасность

- **Минимум 100 000 итераций** для паролей в интерактивных сценариях; 600 000+ для чувствительных систем (OWASP 2023).
- **Salt ≥ 16 байт**, случайный, уникальный для каждого пароля. Никогда не хардкодьте один salt на всё приложение.
- **Пароль не должен попадать в логи.** Предпочтительно читать его из файла / env (`CLI-5`, not implemented).
- **PBKDF2 не защищает от side-channel** при компрометации памяти. В продакшне используйте Argon2id или scrypt.

### Тесты

```bash
python -m unittest tests.test_pbkdf2 tests.test_cli_derive -v
```

Покрытие:
- known-answer векторы PBKDF2-HMAC-SHA256 (1, 2, 4096, 4096 итераций);
- длины 1–100 байт, сверка с `hashlib.pbkdf2_hmac`;
- детерминизм и различие при разных итерациях;
- иерархия ключей: детерминизм, разделение контекстов, длины;
- CLI: формат stdout, случайный salt, `--output` как raw bytes, ошибки.

## Структура проекта

```text
Cryptocore/
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── cli_parser.py
│       ├── csprng.py
│       ├── file_io.py
│       ├── hash_io.py
│       ├── aead/
│       │   ├── __init__.py
│       │   └── etm.py
│       ├── hash/
│       │   ├── __init__.py
│       │   ├── sha256.py
│       │   └── sha3_256.py
│       ├── kdf/
│       │   ├── __init__.py
│       │   ├── hkdf.py
│       │   └── pbkdf2.py
│       ├── mac/
│       │   ├── __init__.py
│       │   └── hmac.py
│       └── modes/
│           ├── __init__.py
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           ├── ctr.py
│           └── gcm.py
├── tests/
│   ├── __init__.py
│   ├── test_pbkdf2.py
│   ├── test_cli_derive.py
│   ├── test_cli_dgst.py
│   ├── test_cli_gcm.py
│   ├── test_cli_keygen.py
│   ├── test_csprng.py
│   ├── test_ecb.py
│   ├── test_etm.py
│   ├── test_gcm.py
│   ├── test_hash.py
│   ├── test_hmac.py
│   ├── test_modes.py
│   └── test_openssl.py
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```