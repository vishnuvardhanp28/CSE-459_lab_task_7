from tinyec import registry
import secrets

def compress_point(point):
    """Compress an ECC point to a readable hex string."""
    return f"x={hex(point.x)}, y parity={point.y % 2}"

def ecc_key_exchange(curve_name):
    try:
        # Get the curve
        curve = registry.get_curve(curve_name)
        
        # Generate private keys
        private_key1 = secrets.randbelow(curve.field.n)
        private_key2 = secrets.randbelow(curve.field.n)
        
        # Generate public keys
        public_key1 = private_key1 * curve.g
        public_key2 = private_key2 * curve.g
        
        # Generate shared secret
        shared_secret1 = private_key1 * public_key2
        shared_secret2 = private_key2 * public_key1
        
        # Display results
        print(f"\nCurve: {curve_name}")
        print(f"Private Key 1: {hex(private_key1)}")
        print(f"Public Key 1: {compress_point(public_key1)}")
        print(f"Private Key 2: {hex(private_key2)}")
        print(f"Public Key 2: {compress_point(public_key2)}")
        print(f"Shared Secret 1: {compress_point(shared_secret1)}")
        print(f"Shared Secret 2: {compress_point(shared_secret2)}")
        print(f"Shared Secrets Match: {shared_secret1 == shared_secret2}")
        
        return shared_secret1
    except Exception as e:
        print(f"Error with curve {curve_name}: {e}")
        return None

# Test with two different curves
curve1 = "secp256r1"      # NIST P-256
curve2 = "brainpoolP256r1" # Brainpool P-256

print("Performing ECC Key Exchange...")
shared_secret_curve1 = ecc_key_exchange(curve1)
shared_secret_curve2 = ecc_key_exchange(curve2)