"""Algorithm 3 & Algorithm 4: Encrypted K-Means Clustering and Decryption.

Based on:
  T. B. Ogunseyi and O. M. Adedayo, "Cryptographic Techniques for Data Privacy
  in Digital Forensics", IEEE Access, vol. 11, pp. 142392-142408, 2023.

Algorithm 3: K-Means Computation on Encrypted Data
  Input: An encrypted case-relevant keywords Crv'_kw = Enc[k_1 ∩ k_2 ∩ ... ∩ k_m],
         number of clusters q, termination condition mu.
  Output: Encrypted Cluster C' = (c'_1, c'_2, ..., c'_q)

Algorithm 4: Decryption
  Input: Private key Prikey = w_i, encrypted cluster C' = (c'_1, c'_2, ..., c'_q)
  Output: A set of clusters in plaintext C = (c_1, c_2, ..., c_q)
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Sequence

from .keygen import PrivateKey, PublicKey
from .encrypt import Algorithm2, centered_mod


@dataclass
class EncryptedArtifact:
    """An artifact with its opaque ID and bit-sliced ciphertext vector Cr'_kwt."""
    artifact_id: str
    file_path: str
    # Cr_kwt_prime: [ [cipher_bits for feat_0], [cipher_bits for feat_1], ... ]
    # Each cipher_bit is a decimal string or int
    ciphertext_vector: list[list[str]]
    # Optional debug audit features (strictly for tests/debugging, NEVER used by kmeans or decrypt)
    audit_features: list[int] | None = None


@dataclass
class EncryptedCluster:
    """A cluster containing encrypted artifacts and its centroid representation."""
    cluster_id: int
    name: str  # e.g., "C'_1 (High Suspicion)" or "C'_2 (Low Suspicion)"
    artifact_ids: list[str]
    # Centroid represented as average bit-vector ciphertexts or representative point
    centroid_cipher: list[list[str]]


@dataclass
class DecryptedClusterResult:
    """Plaintext interpretation of a cluster after Algorithm 4."""
    cluster_id: int
    name: str
    risk_level: str  # "HIGH SUSPICION - DELIBERATE CONCEALMENT" vs "LOW SUSPICION - ROUTINE"
    artifact_count: int
    artifact_ids: list[str]
    file_paths: list[str]
    average_features: list[float]  # [avg_keyword_count, avg_concealment_score]
    records: list[dict]


# ---------------------------------------------------------------------------
# Algorithm 4: Decryption
# ---------------------------------------------------------------------------

def decrypt_bit(ciphertext: int | str, private_key: PrivateKey, modulus_d: int) -> int:
    """Decrypt a single bit using Algorithm 4: b = [c * w_0]_d (mod 2)."""
    c = int(ciphertext)
    w0 = int(private_key.w[0])
    return centered_mod(c * w0, modulus_d) % 2


def decrypt_unsigned(
    cipher_bits: Sequence[int | str],
    private_key: PrivateKey,
    modulus_d: int,
    *,
    bit_width: int = 8,
) -> int:
    """Decrypt an unsigned integer encoded LSB-first into bit_width ciphertexts."""
    recovered = 0
    for i, cb in enumerate(cipher_bits[:bit_width]):
        b = decrypt_bit(cb, private_key, modulus_d)
        recovered |= (b << i)
    return recovered


def decrypt_vector(
    ciphertext_vector: list[list[str]],
    private_key: PrivateKey,
    modulus_d: int,
    *,
    bit_width: int = 8,
) -> list[int]:
    """Decrypt a feature vector V_i = [keyword_count, concealment_score]."""
    return [
        decrypt_unsigned(cb_list, private_key, modulus_d, bit_width=bit_width)
        for cb_list in ciphertext_vector
    ]


# ---------------------------------------------------------------------------
# Algorithm 3: K-Means Computation on Encrypted Data
# ---------------------------------------------------------------------------

def _cipher_vector_magnitude(c_vec: list[list[str]]) -> float:
    """Approximate distance metric computed over ciphertext integers for clustering."""
    # Sum of absolute centered values across feature bits
    total = 0.0
    for feat_bits in c_vec:
        feat_val = sum(abs(int(b)) for b in feat_bits)
        total += feat_val
    return total


def encrypted_distance(v1: list[list[str]], v2: list[list[str]]) -> float:
    """Homomorphic distance metric between two encrypted feature vectors.
    
    Computes component-wise difference on ciphertext domain with safe bit scaling.
    """
    total_sq = 0
    for f in range(min(len(v1), len(v2))):
        bits1, bits2 = v1[f], v2[f]
        for b in range(min(len(bits1), len(bits2))):
            diff = abs(int(bits1[b]) - int(bits2[b]))
            if diff.bit_length() > 50:
                diff >>= (diff.bit_length() - 50)
            total_sq += diff * diff
    return math.sqrt(float(total_sq))


def encrypted_kmeans(
    artifacts: list[EncryptedArtifact],
    *,
    q: int = 2,
    max_iter: int = 20,
    mu: float = 1e-3,
    seed: int | None = 42,
) -> list[EncryptedCluster]:
    """Run Algorithm 3: K-Means Computation on Encrypted Data Crv'_kw.
    
    Partitions the encrypted candidates into q clusters (e.g. q=2: High vs Low Suspicion)
    directly in the ciphertext space without decrypting the underlying plaintexts.
    """
    if not artifacts:
        return []

    if len(artifacts) <= q:
        # Edge case: fewer artifacts than clusters
        return [
            EncryptedCluster(
                cluster_id=i + 1,
                name=f"C'_{i + 1}",
                artifact_ids=[art.artifact_id],
                centroid_cipher=art.ciphertext_vector,
            )
            for i, art in enumerate(artifacts)
        ]

    rng = random.Random(seed)

    # 1. K-Means++ initialization directly in ciphertext space
    first_idx = rng.randrange(len(artifacts))
    centroids = [artifacts[first_idx].ciphertext_vector]
    for _ in range(1, q):
        dists = [
            min(encrypted_distance(art.ciphertext_vector, c) for c in centroids)
            for art in artifacts
        ]
        next_idx = dists.index(max(dists))
        centroids.append(artifacts[next_idx].ciphertext_vector)

    assignments = [0] * len(artifacts)

    for iteration in range(max_iter):
        # 2. For each artifact, assign to closest centroid using homomorphic encrypted distance
        new_assignments = []
        for art in artifacts:
            dists = [
                encrypted_distance(art.ciphertext_vector, centroids[j])
                for j in range(q)
            ]
            closest = int(min(range(q), key=lambda j: dists[j]))
            new_assignments.append(closest)

        # Check convergence
        if new_assignments == assignments and iteration > 0:
            break
        assignments = new_assignments

        # 3. Update centroids (component-wise average of ciphertext values directly in ciphertext space)
        new_centroids = []
        for j in range(q):
            cluster_arts = [artifacts[k] for k in range(len(artifacts)) if assignments[k] == j]
            if not cluster_arts:
                new_centroids.append(centroids[j])
                continue

            num_feats = len(cluster_arts[0].ciphertext_vector)
            num_bits = len(cluster_arts[0].ciphertext_vector[0])
            avg_vector = []
            for f in range(num_feats):
                avg_bits = []
                for b in range(num_bits):
                    avg_val = sum(int(a.ciphertext_vector[f][b]) for a in cluster_arts) // len(cluster_arts)
                    avg_bits.append(str(avg_val))
                avg_vector.append(avg_bits)
            new_centroids.append(avg_vector)

        # 4. Termination check via max shift on ciphertext domain
        shift = max(encrypted_distance(centroids[j], new_centroids[j]) for j in range(q))
        centroids = new_centroids
        if shift <= mu:
            break

    # Build resulting encrypted clusters
    clusters = []
    for j in range(q):
        cluster_arts = [artifacts[k] for k in range(len(artifacts)) if assignments[k] == j]
        cluster_name = f"C'_{j + 1}"
        clusters.append(
            EncryptedCluster(
                cluster_id=j + 1,
                name=cluster_name,
                artifact_ids=[a.artifact_id for a in cluster_arts],
                centroid_cipher=centroids[j],
            )
        )
    return clusters


# ---------------------------------------------------------------------------
# Decrypt and Evaluate Clusters (Algorithm 4 in Forensic Presentation)
# ---------------------------------------------------------------------------

def decrypt_clusters(
    clusters: list[EncryptedCluster],
    artifacts: list[EncryptedArtifact],
    private_key: PrivateKey,
    modulus_d: int,
    *,
    bit_width: int = 8,
) -> list[DecryptedClusterResult]:
    """Decrypt the clusters and identify which is the High Suspicion group."""
    art_map = {a.artifact_id: a for a in artifacts}
    results = []

    for cluster in clusters:
        cluster_arts = [art_map[aid] for aid in cluster.artifact_ids if aid in art_map]
        records = []
        total_feats = [0.0, 0.0]

        for art in cluster_arts:
            # Algorithm 4: Decrypt feature vector directly from ciphertext using Private Key
            dec_vec = decrypt_vector(
                art.ciphertext_vector, private_key, modulus_d, bit_width=bit_width
            )
            # dec_vec: [keyword_count, concealment_score]
            kw_count = dec_vec[0] if len(dec_vec) > 0 else 0
            conceal = dec_vec[1] if len(dec_vec) > 1 else 0

            records.append({
                "artifact_id": art.artifact_id,
                "file_path": art.file_path,
                "keyword_count": kw_count,
                "concealment_score": conceal,
                "V_i": [kw_count, conceal],
            })
            total_feats[0] += kw_count
            total_feats[1] += conceal

        n = max(len(cluster_arts), 1)
        avg_feats = [round(total_feats[0] / n, 2), round(total_feats[1] / n, 2)]

        results.append(
            DecryptedClusterResult(
                cluster_id=cluster.cluster_id,
                name=cluster.name,
                risk_level="PENDING_RANKING",
                artifact_count=len(cluster_arts),
                artifact_ids=cluster.artifact_ids,
                file_paths=[a.file_path for a in cluster_arts],
                average_features=avg_feats,
                records=records,
            )
        )

    # Rank clusters by risk: higher concealment score + keyword count = higher risk
    # Sort descending by (avg concealment score, avg keyword count)
    results.sort(key=lambda c: (c.average_features[1], c.average_features[0]), reverse=True)

    if results:
        for idx, res in enumerate(results):
            cid = idx + 1
            avg_kw, avg_conceal = res.average_features[0], res.average_features[1]
            if res.artifact_count == 0:
                res.risk_level = f"C'_{cid}: EMPTY CLUSTER (NO ARTIFACTS)"
                res.name = f"C'_{cid} (Cụm rỗng)"
            elif idx == 0:
                # Top-ranked cluster: Highest risk and primary focus for selective release
                if avg_conceal > 0:
                    res.risk_level = f"C'_{cid}: HIGH SUSPICION (PRIMARY TARGET / SUSPECTED CONCEALMENT)"
                    res.name = f"C'_{cid} (Nguy cơ cao nhất / Nghi vấn cố ý che giấu hoặc đổi đuôi)"
                else:
                    res.risk_level = f"C'_{cid}: HIGH SUSPICION (PRIMARY TARGET / CONFIDENTIAL CONTENT)"
                    res.name = f"C'_{cid} (Khả nghi cao nhất / Tập trung tài liệu mật)"
            else:
                # Secondary clusters: Lower priority / anomaly
                if avg_conceal > 0 or avg_kw > 0:
                    res.risk_level = f"C'_{cid}: MODERATE SUSPICION (SECONDARY CANDIDATES / LOWER ANOMALY)"
                    res.name = f"C'_{cid} (Khả nghi thứ cấp / Mức độ bất thường thấp hơn)"
                else:
                    res.risk_level = f"C'_{cid}: LOW SUSPICION (ROUTINE FILE)"
                    res.name = f"C'_{cid} (Ít khả nghi / Dữ liệu thông thường)"

    return results
