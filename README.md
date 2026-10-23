# CryptoCore

CLI-инструмент для шифрования/расшифрования файлов: AES-128 в режимах ECB, CBC, CFB, OFB, CTR.

## Возможности

- AES-128 (128-битный ключ, 16 байт);
- Режимы: `ecb`, `cbc`, `cfb`, `ofb`, `ctr`;
- PKCS#7 padding для блочных режимов ECB и CBC;
- Потоковые режимы CFB, OFB, CTR работают без padding (размер данных сохраняется);
- Автоматическая генерация IV (`os.urandom(16)`) для CBC, CFB, OFB, CTR;
- IV сохраняется в первых 16 байтах зашифрованного файла;
- Ключ и IV задаются в hex-формате;
- Работа с текстовыми и бинарными файлами;
- Проверка совместимости с OpenSSL.

## Зависимости

- Python 3.12+
- `pycryptodome >= 3.20.0`
- `openssl` в PATH (для тестов совместимости)

## Сборка / установка

```bash
git clone https://github.com/Katarsis435/Cryptocore.git
cd Cryptocore
python -m venv .venv
.venv\Scripts\activate               # Windows
pip install -r requirements.txt
pip install -e .
```

После `pip install -e .` команда `cryptocore` доступна в терминале из любой папки.

## Использование

### Шифрование

ECB (без IV):
```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

CBC (IV генерируется автоматически):
```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

CFB / OFB / CTR — то же самое, меняется только `--mode`:
```bash
cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

### Расшифрование

IV читается автоматически из первых 16 байт файла:
```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

IV передан вручную через `--iv` (hex, 32 символа = 16 байт):
```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 101112131415161718191a1b1c1d1e1f --input ciphertext.bin --output decrypted.txt
```

ECB — без IV:
```bash
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

### Аргументы

| Аргумент       | Описание                                                                 |
|----------------|--------------------------------------------------------------------------|
| `--algorithm`  | Шифр. Поддерживается только `aes`.                                       |
| `--mode`       | Режим: `ecb`, `cbc`, `cfb`, `ofb`, `ctr`.                                |
| `--encrypt`    | Флаг шифрования (взаимоисключим с `--decrypt`).                          |
| `--decrypt`    | Флаг расшифрования.                                                      |
| `--key`        | 32 hex-символа = 16 байт (AES-128).                                      |
| `--iv`         | 32 hex-символа = 16 байт. Только при `--decrypt` и только для CBC/CFB/OFB/CTR. |
| `--input`      | Путь к входному файлу.                                                   |
| `--output`     | Путь к выходному файлу (если не указан — имя сгенерируется автоматически). |

## Работа с IV

Для режимов **CBC, CFB, OFB, CTR**:

- **При шифровании:** IV генерируется автоматически через `os.urandom(16)`. Флаг `--iv` при шифровании **запрещён** (программа завершится с ошибкой).
- **При расшифровании:** IV берётся либо из `--iv`, либо из первых 16 байт входного файла.

Размер IV всегда 16 байт (размер блока AES).

### Формат зашифрованного файла

```
CBC, CFB, OFB, CTR:   [16 байт IV][зашифрованные данные]
ECB:                  [зашифрованные данные]
```

## Padding

- **ECB, CBC** — используется **PKCS#7**. Открытый текст дополняется до кратности 16 байтам. Если данные уже кратны 16, добавляется целый блок padding'а.
- **CFB, OFB, CTR** — padding **не используется**. Размер данных после шифрования совпадает с исходным.

## Тест полного цикла

Пример для CBC (для других режимов замени `--mode cbc` на `--mode ecb|cfb|ofb|ctr`):

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Проверка совпадения:
```powershell
Compare-Object (Get-Content plaintext.txt) (Get-Content decrypted.txt)   # PowerShell — пусто = совпадают
fc /b plaintext.txt decrypted.txt                                         # cmd.exe
diff plaintext.txt decrypted.txt                                          # Linux/macOS
```

## Проверка совместимости с OpenSSL

### Автоматическая проверка

```bash
python -m unittest discover -s tests -v
```

Файл `tests/test_openssl.py` автоматически проверяет все режимы (ECB, CBC, CFB, OFB, CTR) в **обе стороны**:

1. **CryptoCore → OpenSSL:** шифруем нашим инструментом, расшифровываем OpenSSL, сравниваем с оригиналом.
2. **OpenSSL → CryptoCore:** шифруем OpenSSL, расшифровываем нашим инструментом, сравниваем с оригиналом.
3. **Побайтовое совпадение шифротекста** — самый строгий тест.

Если `openssl` не установлен в PATH, тесты автоматически скипаются (не падают).

### Ручная проверка

#### CryptoCore → OpenSSL (пример для CBC)

1. Зашифруй нашим инструментом:
```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cipher.bin
```

2. Извлеки IV (первые 16 байт) и ciphertext (остальное) — PowerShell:
```powershell
$data = [System.IO.File]::ReadAllBytes("cipher.bin")
[System.IO.File]::WriteAllBytes("ct_only.bin", $data[16..($data.Length - 1)])
$iv = -join ($data[0..15] | ForEach-Object { $_.ToString("x2") })
```

3. Расшифруй через OpenSSL:
```bash
openssl enc -aes-128-cbc -d -K 000102030405060708090a0b0c0d0e0f -iv $iv -in ct_only.bin -out decrypted.txt
```

4. Сравни с исходным:
```powershell
fc /b plaintext.txt decrypted.txt
```

Для других режимов меняется только суффикс OpenSSL:
- CBC → `-aes-128-cbc`
- CFB → `-aes-128-cfb`
- OFB → `-aes-128-ofb`
- CTR → `-aes-128-ctr`

#### OpenSSL → CryptoCore (пример для CTR)

1. Зашифруй через OpenSSL (IV задаём явно):
```bash
openssl enc -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv 101112131415161718191a1b1c1d1e1f -in plaintext.txt -out openssl_cipher.bin
```

2. Расшифруй нашим инструментом (IV тот же):
```bash
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 101112131415161718191a1b1c1d1e1f --input openssl_cipher.bin --output decrypted.txt
```

3. Сравни:
```powershell
fc /b plaintext.txt decrypted.txt
```

Для других режимов меняется `--mode` и суффикс OpenSSL.

#### ECB

ECB не использует IV и всегда применяет PKCS#7:
```bash
openssl enc -aes-128-ecb -d -K 000102030405060708090a0b0c0d0e0f -in cipher.bin -out decrypted.txt
```

## Тесты

```bash
# все тесты
python -m unittest discover -s tests -v

# или через pytest, если установлен
pytest -q
```

Состав тестов:
- `tests/test_ecb.py` — ECB, PKCS#7, NIST-вектор;
- `tests/test_modes.py` — CBC, CFB, OFB, CTR, round-trip, отсутствие padding у потоковых режимов;
- `tests/test_openssl.py` — автоматическая сверка всех режимов с OpenSSL в обе стороны.

## Обработка ошибок

- Неверный размер ключа (`--key 1234`) → ошибка, код возврата ≠ 0.
- Одновременное `--encrypt` и `--decrypt` → ошибка argparse.
- `--iv` при шифровании → ошибка (IV генерируется автоматически).
- `--iv` в режиме ECB → ошибка (IV не используется).
- Входной файл короче 16 байт при расшифровании CBC/CFB/OFB/CTR без `--iv` → ошибка.

## Структура проекта

```
Cryptocore/
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── cli_parser.py
│       ├── file_io.py
│       └── modes/
│           ├── __init__.py
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           └── ctr.py
├── tests/
│   ├── __init__.py
│   ├── test_ecb.py
│   ├── test_modes.py
│   └── test_openssl.py
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Зависимости

- `pycryptodome` — примитив AES (мы используем его только как AES-примитив для одного блока; логика ECB, CBC, CFB, OFB, CTR реализована вручную);
- `openssl` (внешний бинарь) — только для тестов совместимости;
- `pytest` (опционально) — для более удобного запуска тестов.

## Хеширование файлов (`dgst`)

Спринт 4 добавляет подкоманду `dgst` для вычисления хешей. Она **отделена** от шифрования и не принимает `--key`, `--mode`, `--encrypt`, `--decrypt`, `--iv`.

### Использование

```bash
cryptocore dgst --algorithm sha256 --input document.pdf
# 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5  document.pdf
```

С записью в файл:
```bash
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

Чтение из stdin (`-`):
```bash
echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -
```

### Аргументы `dgst`

| Аргумент       | Описание                                                         |
|----------------|------------------------------------------------------------------|
| `--algorithm`  | `sha256` или `sha3-256`.                                         |
| `--input`      | Путь к файлу, или `-` для stdin.                                 |
| `--output`     | (опционально) Записать `HASH  FILE` в этот файл.                 |

Формат вывода — совместим с `sha256sum` / `sha3sum`:
```
<hash_hex>  <file_path>
```

### Реализованные алгоритмы

- **SHA-256** — реализован **с нуля** по NIST FIPS 180-4 (Merkle–Damgård, 64 раунда, 512-битные блоки, padding `0x80 || 0x00... || length_bits`).
- **SHA3-256** — реализован **с нуля** по NIST FIPS 202 (Keccak-f[1600], rate = 1088 бит, capacity = 512 бит, padding `0x06 || 0x00... || 0x80`).

Оба алгоритма:
- обрабатывают вход произвольной длины (включая пустые и очень большие файлы);
- читают данные **по частям** (по 8 КБ), память O(1) независимо от размера;
- возвращают hex в нижнем регистре (64 символа).

### Свойства безопасности

- **SHA-256**: криптостойкая 256-битная хеш-функция; устойчива к коллизиям (лучшая известная атака ~2^128 операций); стандарт де-факто для контрольных сумм и цифровых подписей.
- **SHA3-256**: 256-битная хеш-функция на основе Keccak-губки; не имеет структуры Merkle–Damgård, поэтому **не подвержена length-extension** атакам; утверждена NIST в 2015.

⚠️ **Хеш — это не аутентификация.** SHA-256/ SHA3-256 дают целостность, но без ключа. Для аутентификации используют HMAC или подписи — это тема будущих спринтов.

### Тесты

```bash
python -m unittest discover -s tests -v
```

Все тесты включают:
- NIST known-answer векторы для SHA-256 и SHA3-256;
- сверку с Python `hashlib` для десятков размеров входа;
- сверку с `sha256sum` / `sha3sum` (при наличии);
- тест пустого файла и файла 5 МБ;
- тест лавинного эффекта;
- CLI-тесты на формат вывода и на отсутствие лишних аргументов у `dgst`.

### Ручная сверка с системными утилитами

```powershell
# Windows: используй certutil
certutil -hashfile document.pdf SHA256
# или через Git Bash / WSL:
sha256sum document.pdf
sha3sum -a 256 document.pdf

cryptocore dgst --algorithm sha256 --input document.pdf
# хеши должны совпасть
```


