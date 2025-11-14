import random
from math import gcd

# some helpful number theory functions

def is_prime(n: int) -> bool:
    """
    Simple primality test using trial division.
    This is fine for numbers < 1,000,000.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Check odd divisors up to sqrt(n)
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def generate_random_prime(max_value: int = 1_000_000) -> int:
    """
    Generate a random prime less than max_value.
    We keep picking random odd numbers until we find a prime.
    """
    while True:
        # Ensure it's at least 3 and odd
        candidate = random.randint(3, max_value)
        if candidate % 2 == 0:
            candidate += 1
        # Increment by 2 until we find a prime (wrap if needed)
        while candidate < max_value:
            if is_prime(candidate):
                return candidate
            candidate += 2


def extended_gcd(a: int, b: int):
    """
    Extended Euclidean Algorithm.
    Returns (g, x, y) such that: a*x + b*y = g = gcd(a, b)
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modinv(a: int, m: int) -> int:
    """
    Modular inverse of a modulo m.
    Finds x such that (a * x) % m == 1.
    Assumes gcd(a, m) == 1.
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist (a and m are not coprime).")
    return x % m


# RSA key generation

def generate_keys():
    """
    Generate RSA keys:
    - pick random primes p and q (< 1,000,000)
    - compute n, phi(n)
    - choose e such that gcd(e, phi) = 1
    - compute d as modular inverse of e mod phi
    Returns (p, q, n, e, d)
    """

    # Generate two distinct random primes p and q
    p = generate_random_prime(1_000_000)
    q = generate_random_prime(1_000_000)
    while q == p:
        q = generate_random_prime(1_000_000)

    n = p * q              # modulus
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    # Common choice is 65537, but if that doesn't work we pick a random odd e.
    e = 65537
    if gcd(e, phi) != 1:
        # Fallback: pick a random 'e'
        while True:
            e = random.randrange(3, phi, 2)  # random odd number
            if gcd(e, phi) == 1:
                break

    # 3. Compute d, the modular inverse of e modulo phi
    d = modinv(e, phi)

    return p, q, n, e, d


# ----------------------------
# RSA encryption / decryption
# ----------------------------

def encrypt_message(message: str, e: int, n: int):
    """
    Encrypt a string message using RSA.
    We convert each character to its ASCII code (ord)
    and encrypt that integer separately.
    Returns a list of integers (ciphertext blocks).
    """
    ciphertext_blocks = []
    for ch in message:
        m_val = ord(ch)                # convert char to integer (0-255)
        c_val = pow(m_val, e, n)       # RSA encryption: c = m^e mod n
        ciphertext_blocks.append(c_val)
    return ciphertext_blocks


def decrypt_message(ciphertext_blocks, d: int, n: int):
    """
    Decrypt a list of integer ciphertext blocks using RSA.
    Each block is decrypted and converted back to a character.
    """
    chars = []
    for c_val in ciphertext_blocks:
        m_val = pow(c_val, d, n)       # RSA decryption: m = c^d mod n
        chars.append(chr(m_val))       # convert integer back to character
    return "".join(chars)


# Main program

def main():
    # Take message M as input
    message = input("Enter a message to encrypt: ")

    # Generate keys and print p, q, n, e, d
    p, q, n, e, d = generate_keys()
    print("\nGenerated RSA parameters:")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p * q = {n}")
    print(f"e = {e}")
    print(f"d = {d}")

    # Encrypt the message and print ciphertext C
    ciphertext = encrypt_message(message, e, n)
    print("\nCiphertext:")
    print(ciphertext)

    # Decrypt ciphertext C and print original message M
    decrypted_message = decrypt_message(ciphertext, d, n)
    print("\nDecrypted message:")
    print(decrypted_message)


if __name__ == "__main__":
    main()
