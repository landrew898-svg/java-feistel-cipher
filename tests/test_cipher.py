import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CipherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        suffix = '.exe' if os.name == 'nt' else ''
        home = os.environ.get('JAVA_HOME')
        cls.java = str(Path(home) / 'bin' / ('java' + suffix)) if home else shutil.which('java')
        javac = str(Path(home) / 'bin' / ('javac' + suffix)) if home else shutil.which('javac')
        if not cls.java or not javac:
            raise RuntimeError('Install a JDK and set JAVA_HOME or add its bin directory to PATH.')
        cls.temp = tempfile.TemporaryDirectory(prefix='cipher-check-', dir=ROOT)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        subprocess.run([javac, '-d', str(cls.work), str(ROOT / 'src/FeistelCipher.java')],
                       check=True, capture_output=True, text=True, timeout=30)

    def invoke(self, *args):
        return subprocess.run([self.java, '-cp', str(self.work), 'FeistelCipher', *map(str, args)],
                              capture_output=True, text=True, timeout=10)

    def transform(self, data, key, operation, mode):
        source, output = self.work / 'input.bin', self.work / 'output.bin'
        source.write_bytes(data)
        result = self.invoke(source, output, key, operation, mode)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_bytes()

    def test_round_trips(self):
        for mode in [8, 16]:
            for key in ['A', 'Secret', 'R2R2R2']:
                for data in [b'', b'Hello!', b'Hello', bytes(range(256)), b'A\0\0', b'\0\0']:
                    with self.subTest(mode=mode, key=key, length=len(data)):
                        encrypted = self.transform(data, key, 'e', mode)
                        recovered = self.transform(encrypted, key, 'd', mode)
                        expected = data + b'\0' if mode == 16 and len(data) % 2 else data
                        self.assertEqual(recovered, expected)

    def test_vectors(self):
        vectors = json.loads((ROOT / 'examples/vectors.json').read_text())
        for vector in vectors:
            with self.subTest(mode=vector['mode']):
                plain = bytes.fromhex(vector['plaintext_hex'])
                cipher = bytes.fromhex(vector['ciphertext_hex'])
                self.assertEqual(self.transform(plain, vector['key'], 'e', vector['mode']), cipher)
                self.assertEqual(self.transform(cipher, vector['key'], 'd', vector['mode']), plain)

    def test_invalid_arguments_leave_output_untouched(self):
        source, output = self.work / 'invalid-input.bin', self.work / 'sentinel.bin'
        source.write_bytes(b'odd')
        for key, op, mode in [('', 'e', '8'), ('Secret', 'bad', '8'),
                              ('Secret', 'e', '12'), ('Secret', 'e', 'x'), ('Secret', 'd', '16')]:
            with self.subTest(key=key, op=op, mode=mode):
                output.write_bytes(b'preserve me')
                result = self.invoke(source, output, key, op, mode)
                self.assertEqual(result.returncode, 1)
                self.assertIn('Error:', result.stderr)
                self.assertEqual(output.read_bytes(), b'preserve me')

    def test_usage_and_file_errors(self):
        source = self.work / 'same.bin'
        source.write_bytes(b'keep')
        for args in [[], [self.work / 'missing.bin', self.work / 'unused.bin', 'Secret', 'e', '8'],
                     [source, source, 'Secret', 'e', '8'],
                     [source, self.work, 'Secret', 'e', '8']]:
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('Exception in thread', result.stderr)
        self.assertEqual(source.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
