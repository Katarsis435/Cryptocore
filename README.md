# CryptoCore

CLI-инструмент для шифрования/расшифрования файлов: AES-128 в режиме ECB с дополнением PKCS#7.

## Зависимости

- Python 3.12+
- `pycryptodome >= 3.20.0`

## Сборка / установка

```bash
git clone https://github.com/Katarsis435/Cryptocore.git
cd cryptocore
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

## Использование

```bash
# Шифрование
python cryptocore.py --algorithm aes --mode ecb --encrypt ^
    --key 000102030405060708090a0b0c0d0e0f ^
    --input plaintext.txt --output ciphertext.bin

# Расшифрование
python cryptocore.py --algorithm aes --mode ecb --decrypt ^
    --key 000102030405060708090a0b0c0d0e0f ^
    --input ciphertext.bin --output decrypted.txt
```

### Аргументы

| Аргумент       | Описание                                              |
|----------------|-------------------------------------------------------|
| `--algorithm`  | Шифр. Поддерживается только `aes`.                    |
| `--mode`       | Режим. Поддерживается только `ecb`.                   |
| `--encrypt`    | Флаг шифрования (взаимоисключим с `--decrypt`).       |
| `--decrypt`    | Флаг расшифрования.                                   |
| `--key`        | 32 hex-символа = 16 байт (AES-128).                   |
| `--input`      | Путь к входному файлу.                                |
| `--output`     | Путь к выходному файлу (если не указан — имя сгенерируется автоматически). |

## Тест полного цикла

```bash
python cryptocore.py --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
python cryptocore.py --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt

# Проверка совпадения:
Compare-Object (Get-Content plaintext.txt) (Get-Content decrypted.txt)   # PowerShell — пусто = совпадают
fc plaintext.txt decrypted.txt                                            # cmd.exe
diff plaintext.txt decrypted.txt                                          # Linux/macOS — различий не должно быть
```

## Сверка с OpenSSL

```bash
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.txt -out openssl.bin -nopad
# openssl.bin должен совпадать с ciphertext.bin (только для данных, кратных 16 байтам)
```

## Тесты

```bash
python -m unittest discover -s tests -v
```