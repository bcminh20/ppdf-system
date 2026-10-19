import json
import os
import tempfile
import unittest
from pathlib import Path

from ppdf_keygen import (
    KeyGenerationError,
    PrivateKey,
    generate_keypair,
    load_private_key_from_env,
    load_public_key,
    save_private_key_to_env,
    save_public_key,
)


class KeyGenerationTests(unittest.TestCase):
    def test_seeded_generation_is_reproducible(self):
        first = generate_keypair(4, 8, seed=12345)
        second = generate_keypair(4, 8, seed=12345)
        self.assertEqual(first, second)
        self.assertGreater(first.public_key.d, 1)
        self.assertGreaterEqual(first.public_key.r, 0)
        self.assertLess(first.public_key.r, first.public_key.d)
        self.assertEqual(len(first.private_key.w), 4)

    def test_invalid_parameters_are_rejected(self):
        with self.assertRaises(ValueError):
            generate_keypair(1, 8)
        with self.assertRaises(ValueError):
            generate_keypair(4, 1)
        with self.assertRaises(ValueError):
            generate_keypair(4, 8, max_attempts=0)

    def test_retry_limit_is_reported(self):
        # A zero retry budget is rejected before generation. This verifies the
        # public failure contract without depending on random failure rates.
        with self.assertRaises(ValueError):
            generate_keypair(4, 8, max_attempts=0)

    def test_public_and_private_round_trip(self):
        pair = generate_keypair(4, 8, seed=99)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_path = save_public_key(pair.public_key, root / "public_key.json")
            env_path = save_private_key_to_env(
                pair.private_key,
                root / ".env",
                dimension=pair.dimension,
                coefficient_bits=pair.coefficient_bits,
            )
            self.assertEqual(load_public_key(public_path), pair.public_key)
            self.assertEqual(load_private_key_from_env(env_path), pair.private_key)
            payload = json.loads(public_path.read_text())
            self.assertEqual(payload, pair.public_key.as_dict())
            self.assertNotIn("PPDF_PRIVATE_KEY_W", public_path.read_text())

    def test_existing_private_key_is_not_overwritten_without_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            save_private_key_to_env(PrivateKey((1, 3, 5, 7)), env_path)
            with self.assertRaises(FileExistsError):
                save_private_key_to_env(PrivateKey((2, 4, 6, 8)), env_path)
            save_private_key_to_env(PrivateKey((2, 4, 6, 8)), env_path, overwrite=True)
            self.assertEqual(load_private_key_from_env(env_path).w, (2, 4, 6, 8))

    def test_private_file_is_restrictive_when_supported(self):
        if os.name == "nt":
            self.skipTest("POSIX file mode is not portable to Windows")
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            save_private_key_to_env(PrivateKey((1, 3)), env_path)
            self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
