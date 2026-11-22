import unittest
from ppdf.he.keygen import generate_keypair
from ppdf.he.encrypt import Algorithm2
from ppdf.he.kmeans import (
    EncryptedArtifact,
    encrypted_kmeans,
    decrypt_bit,
    decrypt_unsigned,
    decrypt_vector,
    decrypt_clusters,
)


class KMeansTests(unittest.TestCase):
    def setUp(self):
        # Generate small keypair for testing
        self.pair = generate_keypair(dimension=4, coefficient_bits=8, seed=42)
        self.cipher = Algorithm2(self.pair.public_key, dimension=4)
        self.d = self.pair.public_key.d
        self.priv = self.pair.private_key

    def test_bit_and_integer_decryption(self):
        # Test Algorithm 4 single bit decryption
        for b in (0, 1):
            c = self.cipher.encrypt_bit(b)
            dec_b = decrypt_bit(c, self.priv, self.d)
            self.assertEqual(dec_b, b)

        # Test Algorithm 4 unsigned integer decryption
        for val in (0, 1, 5, 15, 42, 100):
            cipher_bits = self.cipher.encrypt_unsigned(val, bit_width=8)
            dec_val = decrypt_unsigned(cipher_bits, self.priv, self.d, bit_width=8)
            self.assertEqual(dec_val, val)

    def test_vector_decryption(self):
        # V_i = [keyword_count, concealment_score]
        v_original = [15, 10]
        c_vec = self.cipher.encrypt_vector(v_original, bit_width=8)
        v_dec = decrypt_vector(c_vec, self.priv, self.d, bit_width=8)
        self.assertEqual(v_dec, v_original)

    def test_encrypted_kmeans_clustering(self):
        # Simulate 4 artifacts:
        # F1: normal file [15, 1]
        # F2: routine proposal [8, 2]
        # F3: highly suspicious hidden file [42, 10]
        # F4: another suspicious file [38, 9]
        data = [
            ("F1", "PC/emails.csv", [15, 1]),
            ("F2", "RM1/proposal.doc", [8, 2]),
            ("F3", "RM2/$OrphanFiles/PRICIN~1.bak", [42, 10]),
            ("F4", "RM2/$OrphanFiles/SECRET~1.bin", [38, 9]),
        ]

        encrypted_artifacts = [
            EncryptedArtifact(
                artifact_id=aid,
                file_path=path,
                ciphertext_vector=self.cipher.encrypt_vector(vec, bit_width=8),
                features=vec,
            )
            for aid, path, vec in data
        ]

        # Run Algorithm 3: K-Means on encrypted data (q=2)
        clusters = encrypted_kmeans(encrypted_artifacts, q=2, max_iter=10, seed=42)
        self.assertEqual(len(clusters), 2)

        # Run Algorithm 4: Decrypt clusters
        dec_results = decrypt_clusters(
            clusters, encrypted_artifacts, self.priv, self.d, bit_width=8
        )
        self.assertEqual(len(dec_results), 2)

        # Top ranked cluster must be C'_1 (High Suspicion) with higher concealment score
        high_risk_cluster = dec_results[0]
        low_risk_cluster = dec_results[1]

        self.assertIn("HIGH SUSPICION", high_risk_cluster.risk_level)
        self.assertIn("LOW SUSPICION", low_risk_cluster.risk_level)

        # F3 and F4 should be grouped together in high risk cluster
        self.assertIn("F3", high_risk_cluster.artifact_ids)
        self.assertIn("F4", high_risk_cluster.artifact_ids)
        self.assertIn("F1", low_risk_cluster.artifact_ids)
        self.assertIn("F2", low_risk_cluster.artifact_ids)


if __name__ == "__main__":
    unittest.main()
