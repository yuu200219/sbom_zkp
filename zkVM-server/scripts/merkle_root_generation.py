import hashlib


def sha256_pair(a_hex, b_hex):
    a = bytes.fromhex(a_hex.replace("0x", ""))
    b = bytes.fromhex(b_hex.replace("0x", ""))
    return hashlib.sha256(a + b).hexdigest()


leaf_a = "6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536"
leaf_b = "313233343536373839306162636465666768696a6b6c6d6e6f70717273747576"

print(f"Correct Root: 0x{sha256_pair(leaf_a, leaf_b)}")
