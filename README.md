# JWT JWE Decryption Helper
A lightweight Python utility for decrypting compact JWE tokens using RSA private keys. This tool is intended for debugging and validating encrypted request objects.

## Features

- Decrypts compact JWE tokens using RSA private keys in PEM format  
- Supports password protected private keys  
- Optionally displays the decoded JWE header  
- Outputs decrypted content as UTF8 text or hexadecimal bytes  
- Uses the `jwskate` library for JWE and JWK operations  

## Requirements

- Python 3.8 or above  
- `jwskate` library  

Install dependency:

`pip install jwskate`

## Installation

Save the script as:

`decrypt_jwe.py`

Make it executable:

`chmod +x decrypt_jwe.py`

Or run directly using Python:

`python decrypt_jwe.py`

## Usage

### Basic decryption

```
./decrypt_jwe.py  
--token "<compact_jwe_here>"  
--key-file /path/to/private_key.pem
```  

### Show the JWE header and decode payload

```
./decrypt_jwe.py  
--token "<compact_jwe_here>"  
--key-file /path/to/private_key.pem  
--show-header  
--decode  
```

### Decrypt using a password protected private key
```
./decrypt_jwe.py  
--token "<compact_jwe_here>"  
--key-file /path/to/encrypted_key.pem  
--key-pass "your_password"  
--decode  
```

## Command Line Arguments

| Argument        | Description                                                     |
|-----------------|-----------------------------------------------------------------|
| `--token`       | Compact JWE string to decrypt. Required.                        |
| `--key-file`    | Path to RSA/ECDH private key in PEM format. Required.           |
| `--key-pass`    | Password for encrypted private key PEM files. Optional.         |
| `--show-header` | Prints the decoded JWE protected header. Optional.              |
| `--decode`      | Attempts to print UTF8 decoded payload, falls back to hex.      |


## Output Behaviour

- By default, the decrypted payload is printed in hexadecimal form  
- With `--decode`, the script attempts to output UTF8 text  
- If UTF8 decoding fails, it prints the payload as hex with a warning  
- On decryption failure, the script exits with a descriptive error message  

## Example

```
./decrypt_jwe.py  
--token "$JWE"  
--key-file ./keys/private.pem  
--show-header  
--decode
```  
