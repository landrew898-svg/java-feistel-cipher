# Java Feistel Cipher

A small educational Java implementation of a Feistel network for encrypting and decrypting files. It demonstrates round-key reversal, XOR, swaps, and finite-field multiplication.

## Build and run

Requires JDK 11 or newer; no external libraries or build tools.

```sh
mkdir build
javac -d build src/FeistelCipher.java
java -cp build FeistelCipher examples/message.txt build/encrypted.bin Secret e 8
java -cp build FeistelCipher build/encrypted.bin build/recovered.txt Secret d 8
```

The recovered file matches `examples/message.txt`. Replace `8` with `16` in both commands to try 16-bit blocks. Arguments are:

```text
<input-file> <output-file> <key-string> <e|d> <8|16>
```

Each key character supplies one round key, so `Secret` gives six rounds. Quote keys containing spaces. The low four bits of each Java character are used in 8-bit mode; the low eight bits are used in 16-bit mode. Different strings can therefore produce equivalent round keys.

Input and output must be different files. An existing output file is overwritten. Invalid arguments and file errors produce an error message and exit status 1.

## How it works

Each round transforms `(L, R)` into `(R, L XOR F(R, key))`. The final halves are swapped before output. Decryption uses the same operations with round keys in reverse order.

| Mode | Block size | Half size | Round function |
|---|---|---|---|
| 8 | One byte | Four bits | Multiplication in GF(2^4), modulus `0x13` |
| 16 | Two bytes | Eight bits | Multiplication in GF(2^8), modulus `0x11B` |

## Padding behavior

8-bit mode preserves file length exactly. In 16-bit mode, an odd-length input receives one zero byte before encryption. Decryption retains that byte because the format does not store the original length. Automatically removing zeros would corrupt files that genuinely end in zero bytes. Even-length inputs recover exactly. Odd-length ciphertext is rejected in 16-bit mode.

## Examples and checks

`examples/vectors.json` contains generated plaintext and ciphertext in hexadecimal, with explicit keys and modes. These are regression examples, not independent proof of cryptographic correctness.

Optional automated checks require Python 3.8+ and a JDK. Put `java` and `javac` on PATH, or set `JAVA_HOME` to your JDK directory:

```sh
python -B -m unittest discover -s tests -v
```

Checks compile the source into a temporary directory under the repository, exercise the command line, verify the example vectors, and test round trips, zero padding, invalid options, and file errors. Original sample ciphertexts whose settings could not be verified are excluded.

## Limitations

This is a learning project, unsuitable for protecting sensitive data. Blocks are processed independently and deterministically; there is no randomization, authentication, or password-based key derivation. The small blocks and linear round function make this a toy cipher. Wrong keys and modified ciphertext generally produce output without an error. The entire file is read into memory.

The cipher's original round functions and output format are preserved. Repository cleanup adds argument validation, readable file errors, protection against overwriting the input, explicit padding guidance, and reproducible examples. No claim of compatibility with a standard encryption format is made.
