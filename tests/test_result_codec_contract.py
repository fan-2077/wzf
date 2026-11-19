"""Local lossless-result codec contract; no target, network or business calls.

Emitter tests compile the real emit function and its standard-library imports
from each source AST. They deliberately exclude HTTP argv and Redis connection
top-level code. The missing-dependency case fails at the real early import and
also asserts no connection or HTTP opener was invoked. This is not target
Python/lzma qualification or an end-to-end SREGym run.
"""
from __future__ import annotations

import ast
import base64
import builtins
from contextlib import redirect_stdout
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
STRATEGY = ROOT / 'b0-run/payload/strategy'
sys.path[:0] = [str(STRATEGY), str(ROOT / 'b0-run/payload/common_bridge')]
from common_io import parse_capture


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_emitter(filename):
    path = STRATEGY / 'programs' / filename
    tree = ast.parse(path.read_text(), filename=str(path))
    selected = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == 'emit']
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['emit']


EMITTERS = {name: load_emitter(name) for name in ('http_common.py', 'redis_common.py')}


def emit_bytes(emitter, value):
    output = io.StringIO()
    with redirect_stdout(output):
        emitter(value)
    return output.getvalue().encode()


def capture(stdout):
    return {'exit_code': 0, 'query': {'target_process_terminal': True}, 'stdout': stdout, 'stderr': b''}


def envelope(raw, *, marker='B0_RESULT_XZ', encoding='xz+base64', compressed=None, **changes):
    if compressed is None:
        compressed = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=3)
    value = {'encoding': encoding, 'uncompressed_bytes': len(raw),
             'uncompressed_sha256': sha(raw), 'data_base64': base64.b64encode(compressed).decode()}
    value.update(changes)
    return marker.encode() + b':' + canonical(value) + b'\n'


class ResultEmitterContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.noise = random.Random(20261119).randbytes(6000).hex()
        cls.threshold_values = {}
        # Actual compression, not a mocked byte count. Locate both exact
        # threshold sides without assuming one particular zlib implementation.
        for length in range(6000, 9000):
            value = {'blob': cls.noise[:length]}
            size = len(zlib.compress(canonical(value)))
            if size in (4096, 4097):
                cls.threshold_values.setdefault(size, value)
            if len(cls.threshold_values) == 2:
                break
        if len(cls.threshold_values) != 2:
            raise AssertionError('Actual deterministic compression threshold fixtures unavailable')
        text = random.Random(44499998488).randbytes(30000).hex()
        cls.repeated = {'events': [{'index': index, 'value': text} for index in range(4)]}

    def test_both_real_emit_functions_have_identical_ast(self):
        functions = []
        for name in EMITTERS:
            tree = ast.parse((STRATEGY / 'programs' / name).read_text())
            functions.append(ast.dump(next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == 'emit'), include_attributes=False))
        self.assertEqual(functions[0], functions[1])

    def test_small_zlib_keeps_original_canonical_bytes_and_envelope(self):
        value = {'中文': 'line\n\x00😀', 'count': 0, 'flag': False, 'empty': []}
        raw = canonical(value)
        expected = envelope(raw, marker='B0_RESULT_ZLIB', encoding='zlib+base64', compressed=zlib.compress(raw))
        for name, emitter in EMITTERS.items():
            with self.subTest(emitter=name):
                actual = emit_bytes(emitter, value)
                self.assertEqual(actual, expected)
                self.assertEqual(parse_capture(capture(actual)), value)

    def test_exact_4096_zlib_bytes_do_not_attempt_xz(self):
        value = self.threshold_values[4096]
        self.assertEqual(len(zlib.compress(canonical(value))), 4096)
        for name, emitter in EMITTERS.items():
            with self.subTest(emitter=name), patch.object(lzma, 'compress', side_effect=AssertionError('XZ below threshold')):
                actual = emit_bytes(emitter, value)
            self.assertTrue(actual.startswith(b'B0_RESULT_ZLIB:'))
            self.assertEqual(parse_capture(capture(actual)), value)

    def test_exact_4097_zlib_bytes_attempt_preset3_xz(self):
        value = self.threshold_values[4097]
        raw = canonical(value)
        actual_compress = lzma.compress
        for name, emitter in EMITTERS.items():
            with self.subTest(emitter=name), patch.object(lzma, 'compress', wraps=actual_compress) as observed:
                actual = emit_bytes(emitter, value)
                observed.assert_called_once_with(raw, format=lzma.FORMAT_XZ, preset=3)
            self.assertEqual(parse_capture(capture(actual)), value)

    def test_xz_only_wins_when_shorter_and_exact_original_raw_is_preserved(self):
        cases = [('xz_wins', self.repeated, True), ('zlib_wins', {'blob': self.noise}, False)]
        for label, value, xz_wins in cases:
            raw = canonical(value)
            zbytes = zlib.compress(raw)
            xbytes = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=3)
            self.assertGreater(len(zbytes), 4096)
            self.assertEqual(len(xbytes) < len(zbytes), xz_wins)
            expected_marker = b'B0_RESULT_XZ:' if xz_wins else b'B0_RESULT_ZLIB:'
            outputs = []
            for name, emitter in EMITTERS.items():
                with self.subTest(case=label, emitter=name):
                    actual = emit_bytes(emitter, value)
                    self.assertTrue(actual.startswith(expected_marker))
                    encoded = json.loads(actual.split(b':', 1)[1])
                    self.assertEqual(encoded['uncompressed_bytes'], len(raw))
                    self.assertEqual(encoded['uncompressed_sha256'], sha(raw))
                    self.assertEqual(base64.b64decode(encoded['data_base64'], validate=True), xbytes if xz_wins else zbytes)
                    self.assertEqual(parse_capture(capture(actual)), value)
                    outputs.append(actual)
            self.assertEqual(outputs[0], outputs[1])

    def test_xz_compression_failure_is_not_a_silent_zlib_fallback(self):
        for name, emitter in EMITTERS.items():
            output = io.StringIO()
            with self.subTest(emitter=name), redirect_stdout(output), patch.object(lzma, 'compress', side_effect=lzma.LZMAError('injected compressor failure')):
                with self.assertRaises(lzma.LZMAError):
                    emitter(self.repeated)
            self.assertEqual(output.getvalue(), '')

    def test_missing_lzma_fails_full_module_before_any_business_or_read_connection(self):
        real_import = builtins.__import__
        def missing(name, *args, **kwargs):
            if name == 'lzma':
                raise ImportError('injected missing lzma')
            return real_import(name, *args, **kwargs)
        for relative in ('common_io.py', 'programs/http_common.py', 'programs/redis_common.py'):
            path = STRATEGY / relative
            with self.subTest(module=relative), patch('socket.create_connection') as socket_call, patch('urllib.request.build_opener') as opener, patch.object(builtins, '__import__', side_effect=missing):
                with self.assertRaisesRegex(ImportError, 'injected missing lzma'):
                    exec(compile(path.read_bytes(), str(path), 'exec'), {'__name__': 'isolated_missing_dependency'})
                socket_call.assert_not_called()
                opener.assert_not_called()


class ResultDecoderContract(unittest.TestCase):
    def setUp(self):
        self.value = {'message': '中文\n\u0000😀', 'complete': True, 'entries': []}
        self.raw = canonical(self.value)
        self.xz = lzma.compress(self.raw, format=lzma.FORMAT_XZ, preset=3)

    def assert_rejected(self, stdout):
        with self.assertRaises((RuntimeError, ValueError, lzma.LZMAError, zlib.error)):
            parse_capture(capture(stdout))

    def test_plain_zlib_gzip_and_xz_formats_remain_accepted(self):
        cases = [b'B0_RESULT:' + self.raw + b'\n',
                 envelope(self.raw, marker='B0_RESULT_ZLIB', encoding='zlib+base64', compressed=zlib.compress(self.raw)),
                 envelope(self.raw, marker='B0_RESULT_GZIP', encoding='gzip+base64', compressed=gzip.compress(self.raw, mtime=0)),
                 envelope(self.raw)]
        for stdout in cases:
            with self.subTest(marker=stdout.split(b':', 1)[0]):
                self.assertEqual(parse_capture(capture(b'ordinary startup log\n' + stdout)), self.value)

    def test_truncated_xz_and_corrupt_crc_are_rejected(self):
        corrupted = bytearray(self.xz)
        corrupted[-12] ^= 1  # Corrupt the XZ footer CRC, after complete content.
        for data in [self.xz[:-1], self.xz[:-8], self.xz[:-12], bytes(corrupted)]:
            with self.subTest(length=len(data)):
                self.assert_rejected(envelope(self.raw, compressed=data))

    def test_second_stream_zero_padding_and_trailing_junk_are_rejected(self):
        for suffix in [self.xz, b'\x00' * 4, b'junk', b'\n']:
            with self.subTest(suffix_bytes=len(suffix)):
                self.assert_rejected(envelope(self.raw, compressed=self.xz + suffix))

    def test_alone_format_cannot_impersonate_xz(self):
        alone = lzma.compress(self.raw, format=lzma.FORMAT_ALONE, preset=3)
        self.assert_rejected(envelope(self.raw, compressed=alone))

    def test_valid_large_dictionary_stream_exceeds_decoder_memlimit(self):
        encoded = lzma.compress(self.raw, format=lzma.FORMAT_XZ,
                               filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 64 * 1024 * 1024}])
        self.assertEqual(lzma.decompress(encoded, format=lzma.FORMAT_XZ), self.raw)
        with self.assertRaisesRegex(lzma.LZMAError, 'Memory usage limit'):
            parse_capture(capture(envelope(self.raw, compressed=encoded)))

    def test_underdeclared_high_expansion_cannot_be_accepted(self):
        expanded = canonical({'value': 'a' * (1024 * 1024)})
        self.assert_rejected(envelope(expanded, uncompressed_bytes=16))

    def test_declared_length_and_sha_must_match_exactly(self):
        for changes in [{'uncompressed_bytes': len(self.raw) - 1},
                        {'uncompressed_bytes': len(self.raw) + 1},
                        {'uncompressed_sha256': '0' * 64}]:
            with self.subTest(changes=changes):
                self.assert_rejected(envelope(self.raw, **changes))

    def test_original_64_mib_declaration_limit_and_noninteger_rejection(self):
        for declaration in [True, False, -1, 64 * 1024 * 1024 + 1, str(len(self.raw)), None]:
            with self.subTest(declaration=declaration), patch.object(lzma, 'LZMADecompressor', side_effect=AssertionError('invalid declaration reached decoder')):
                self.assert_rejected(envelope(self.raw, compressed=self.xz, uncompressed_bytes=declaration))

    def test_memlimit_and_declared_plus_one_are_passed_to_real_decoder(self):
        actual_decoder = lzma.LZMADecompressor
        calls = []
        class ObservedDecoder:
            def __init__(self, **kwargs):
                calls.append(('construct', kwargs))
                self.inner = actual_decoder(**kwargs)
            def decompress(self, data, **kwargs):
                calls.append(('decompress', kwargs))
                return self.inner.decompress(data, **kwargs)
            def __getattr__(self, name):
                return getattr(self.inner, name)
        with patch.object(lzma, 'LZMADecompressor', ObservedDecoder):
            self.assertEqual(parse_capture(capture(envelope(self.raw, compressed=self.xz))), self.value)
        self.assertEqual(calls, [('construct', {'format': lzma.FORMAT_XZ, 'memlimit': 64 * 1024 * 1024}),
                                 ('decompress', {'max_length': len(self.raw) + 1})])

    def test_invalid_base64_and_mismatched_encoding_are_rejected(self):
        for changes in [{'data_base64': '%%%='}, {'data_base64': base64.b64encode(self.xz).decode() + '!'},
                        {'encoding': 'zlib+base64'}, {'encoding': 'gzip+base64'}, {'extra': True}]:
            with self.subTest(changes=changes):
                self.assert_rejected(envelope(self.raw, compressed=self.xz, **changes))

    def test_nonobject_or_extra_json_value_is_rejected(self):
        for raw in [b'[]', b'null', b'{}{}', b'']:
            with self.subTest(raw=raw):
                self.assert_rejected(envelope(raw))

    def test_original_terminal_and_single_result_marker_requirements_remain(self):
        valid = envelope(self.raw)
        self.assert_rejected(valid + valid)
        self.assert_rejected(b'B0_RESULT:{}\n' + valid)
        self.assert_rejected(b'no complete result marker\n')
        for changed in [{'exit_code': 1}, {'query': {'target_process_terminal': False}}, {'query': {}}]:
            with self.subTest(changed=changed):
                with self.assertRaises(RuntimeError):
                    parse_capture({**capture(valid), **changed})


if __name__ == '__main__':
    unittest.main(verbosity=2)
