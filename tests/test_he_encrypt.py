import csv
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ppdf.he.encrypt import Algorithm2, centered_mod
from ppdf.he.keygen import PublicKey
from ppdf.he.extract_encrypt import (
    build_features, concealment, detect_format, extract_text, is_mismatch,
    keyword_matches, run, verify_manifest,
)


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        # 2^4 = -1 (mod 17): small algebra fixture, not a secure key.
        self.cipher = Algorithm2(PublicKey(17, 2), 4)

    def test_paper_equation_with_hand_calculated_noise(self):
        self.assertEqual(self.cipher.encrypt_bit(1, noise=[1, -1, 1, 0]), 7)
        self.assertEqual(self.cipher.encrypt_bit(1, noise=[0, 0, 0, 1]), 0)
        self.assertEqual(self.cipher.encrypt_bit(0, noise=[-1, 0, 0, 0]), -2)
        self.assertEqual([centered_mod(v, 17) for v in [8, 9, -9, 17]], [8, -8, 8, 0])

    def test_integer_encoding_preserves_more_than_parity(self):
        with patch.object(Algorithm2, "encrypt_bit", side_effect=lambda b: b):
            bits = self.cipher.encrypt_unsigned(10, bit_width=8)
        self.assertEqual(bits, ["0", "1", "0", "1", "0", "0", "0", "0"])
        self.assertEqual(sum(int(b) << i for i, b in enumerate(bits)), 10)
        with self.assertRaises(ValueError):
            self.cipher.encrypt_unsigned(256, bit_width=8)
        with self.assertRaises(ValueError):
            self.cipher.encrypt_bit(10)
        with self.assertRaises(ValueError):
            self.cipher.encrypt_bit(1, noise=[0, 0, 2, 0])

    def test_key_dimension_mismatch_fails(self):
        with self.assertRaises(ValueError):
            Algorithm2(PublicKey(17, 2), 8)


class ExtractionTests(unittest.TestCase):
    def make_fixture(self, root):
        keywords = ['secret_project', 'Secret Project', 'Secret Project Data']
        xml = '<keyword_lists><keyword_list>' + ''.join(
            f'<keyword literal="true" whole="true">{kw}</keyword>' for kw in keywords
        ) + '</keyword_list></keyword_lists>'
        for name in ['TuKhoa_PC.xml', 'TuKhoa_RM1_RM2.xml']:
            (root / name).write_text(xml)
        (root / 'PC/KeywordHits').mkdir(parents=True)
        original = root / 'RM2/$OrphanFiles/proposal/landscape.png'
        renamed = root / 'RM2/$OrphanFiles_đổi đuôi/proposal/landscape.docx'
        original.parent.mkdir(parents=True)
        renamed.parent.mkdir(parents=True)
        with zipfile.ZipFile(original, 'w') as z:
            z.writestr('word/document.xml', '<w:document xmlns:w="urn:w"><w:p><w:r><w:t>Secret Pro</w:t></w:r><w:r><w:t>ject Data</w:t></w:r></w:p></w:document>')
        renamed.write_bytes(original.read_bytes())
        sha = hashlib.sha256(original.read_bytes()).hexdigest()
        with (renamed.parent.parent / 'doi_duoi_log.csv').open('w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['OldName', 'NewName', 'SHA256', 'Verified'])
            writer.writerow(['landscape.png', 'landscape.docx', sha, 'True'])
        source_path = '/img_rm2/vol/$OrphanFiles/proposal/landscape.png'
        with (root / 'RM2/hits_secret_project.csv').open('w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Keyword', 'File Path'])
            writer.writerow(['secret_project', source_path])
            writer.writerow(['secret_project', source_path])
        entries = [{"path": str(p.relative_to(root)).replace("\\", "/"), "bytes": p.stat().st_size,
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                   for p in sorted(root.rglob('*')) if p.is_file()]
        (root / 'MANIFEST_SHA256.json').write_text(json.dumps(entries))
        return original

    def test_signature_and_text_ignore_disguised_extension(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = self.make_fixture(root)
            self.assertEqual(detect_format(path), 'docx')
            self.assertTrue(is_mismatch(path, 'docx'))
            text, status = extract_text(path, 'docx')
            self.assertIn('Secret Project Data', text)
            self.assertIn('ooxml', status)
        self.assertEqual(keyword_matches('notsecret_project secret_projectX', ['secret_project']), set())
        self.assertEqual(concealment('/$OrphanFiles/x.png', mismatch=True),
                         (5, ['extension_mismatch', 'recovered_path']))

    def test_binary_fallback_covers_utf16_at_unaligned_offsets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'evidence.bin'
            path.write_bytes(b'\xff' + 'Secret Project'.encode('utf-16-le') +
                             b'\xff\xff\xff' + 'secret_project'.encode('utf-16-be'))
            text, _ = extract_text(path, 'unknown')
            self.assertEqual(keyword_matches(text, ['secret project', 'secret_project']),
                             {'secret project', 'secret_project'})

    def test_deduplicates_hit_rows_and_renamed_copies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_fixture(root)
            records, provenance = build_features(root, verify_manifest(root))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['V_i'], [3, 5])
            self.assertEqual(len(records[0]['index_references']), 2)
            self.assertEqual(len(records[0]['local_paths']), 2)
            self.assertEqual(provenance['renamed_alias_count'], 1)

    def test_modified_evidence_fails_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = self.make_fixture(root)
            original.write_bytes(b'modified')
            with self.assertRaises(ValueError):
                verify_manifest(root)

    def test_end_to_end_share_has_only_ciphertext_and_opaque_ids(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / 'evidence'
            root.mkdir()
            self.make_fixture(root)
            key = base / 'public_key.json'
            key.write_text('{"d":17,"r":2}')
            output = base / 'result'
            result = run(root, key, output, dimension=4)
            self.assertEqual(result['encrypted_artifacts'], 1)
            payload_text = (output / 'share/Cr_kwt_prime.json').read_text()
            payload = json.loads(payload_text)
            self.assertNotIn('landscape', payload_text)
            self.assertNotIn('V_i', payload_text)
            self.assertNotIn('matched_keywords', payload_text)
            record = payload['records'][0]
            self.assertEqual(set(record), {'artifact_id', 'Cr_kwt_prime'})
            self.assertEqual([len(v) for v in record['Cr_kwt_prime']], [8, 8])
            self.assertTrue(all(-8 <= int(c) <= 8 for v in record['Cr_kwt_prime'] for c in v))
            with self.assertRaises(FileExistsError):
                run(root, key, output, dimension=4)


if __name__ == '__main__':
    unittest.main()
