"""
Post-Quantum Cryptography Comparison Application

This Flask application compares classical cryptography (ECDSA/ECDH) with 
post-quantum cryptography (ML-DSA/ML-KEM) to demonstrate the differences
in performance and key/signature sizes between the two approaches.

Classical Cryptography (ECDSA/ECDH):
- Based on elliptic curve mathematics
- Vulnerable to quantum computers (Shor's algorithm)
- Smaller key sizes but will be broken by quantum attacks

Post-Quantum Cryptography (ML-DSA/ML-KEM):
- Based on lattice mathematics (Module-LWE problems)
- Resistant to both classical and quantum attacks
- Larger key/signature sizes but provides long-term security
"""

import time
import base64
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dilithium_py.ml_dsa import ML_DSA_44
from kyber_py.ml_kem import ML_KEM_768

app = Flask(__name__)

def bytes_to_base64(data):
    """
    Convert binary data to base64-encoded string for display in HTML.
    
    Cryptographic outputs (signatures, ciphertexts, keys) are binary data
    that cannot be directly displayed as text. Base64 encoding converts
    binary data to ASCII text that can be safely rendered in browsers.
    
    Args:
        data: Binary bytes to encode
        
    Returns:
        Base64-encoded string representation of the binary data
    """
    return base64.b64encode(data).decode('utf-8')

@app.route('/')
def index():
    """
    Render the main page of the application.
    
    This endpoint serves the HTML frontend that allows users to:
    - Enter messages to sign or encrypt
    - View side-by-side comparisons of classical vs post-quantum cryptography
    - See timing and size metrics for each algorithm
    """
    return render_template('index.html')


@app.route('/sign', methods=['POST'])
def sign_message():
    """
    Handle digital signature comparison between ECDSA and ML-DSA.
    
    This endpoint performs two digital signature operations:
    1. ML-DSA (Module-Lattice Digital Signature Algorithm) - Post-quantum
    2. ECDSA (Elliptic Curve Digital Signature Algorithm) - Classical
    
    Digital signatures provide authentication and integrity verification.
    They prove that a message was created by the holder of the private key
    and hasn't been tampered with since signing.
    
    Returns:
        JSON containing timing and size metrics for both algorithms
    """
    # Get message from form input and encode to bytes (UTF-8)
    message = request.form.get('message', '').encode('utf-8')
    
    # Initialize results dictionary with the original message
    results = {'message': message.decode('utf-8')}
    
    # =================================================================
    # ML-DSA (Module-Lattice Digital Signature Algorithm) - Post-Quantum
    # =================================================================
    # ML-DSA is based on hard lattice problems (Module-LWE/Module-LWR)
    # It's one of the NIST-standardized post-quantum signature algorithms
    # Security relies on the difficulty of solving certain lattice problems,
    # which are believed to be hard for both classical and quantum computers
    
    # Generate ML-DSA key pair:
    # - sk (secret key): used for signing messages
    # - pk (public key): used for verifying signatures
    pk, sk = ML_DSA_44.keygen()
    
    # Time the signing operation (creating a digital signature)
    # We use time.perf_counter() for high-precision timing
    start = time.perf_counter()
    ml_dsa_sign = ML_DSA_44.sign(sk, message)
    ml_dsa_sign_time = time.perf_counter() - start
    
    # Time the verification operation (checking if signature is valid)
    start = time.perf_counter()
    # verify() returns True if signature is valid, False otherwise
    ml_dsa_valid = ML_DSA_44.verify(pk, message, ml_dsa_sign)
    ml_dsa_verify_time = time.perf_counter() - start
    
    # Store ML-DSA results with timing and size metrics
    results['ml_dsa'] = {
        'signature': bytes_to_base64(ml_dsa_sign),
        'public_key': bytes_to_base64(pk),
        'sign_time': round(ml_dsa_sign_time * 1000, 3),
        'verify_time': round(ml_dsa_verify_time * 1000, 3),
        'signature_size_bytes': len(ml_dsa_sign),
        'signature_size_bits': len(ml_dsa_sign) * 8,
        'public_key_size_bytes': len(pk),
        'public_key_size_bits': len(pk) * 8
    }
    
    # =================================================================
    # ECDSA (Elliptic Curve Digital Signature Algorithm) - Classical
    # =================================================================
    # ECDSA is based on the discrete logarithm problem on elliptic curves
    # Currently used widely but vulnerable to quantum attacks (Shor's algorithm)
    # Uses SECP256R1 curve (P-256) - a NIST-standardized curve
    
    # Generate ECDSA key pair using P-256 curve
    ecdsa_private = ec.generate_private_key(ec.SECP256R1())
    ecdsa_public = ecdsa_private.public_key()
    
    # Time the ECDSA signing operation
    start = time.perf_counter()
    ecdsa_sign = ecdsa_private.sign(message, ec.ECDSA(hashes.SHA256()))
    ecdsa_sign_time = time.perf_counter() - start
    
    # Time the ECDSA verification operation
    start = time.perf_counter()
    ecdsa_public.verify(ecdsa_sign, message, ec.ECDSA(hashes.SHA256()))
    ecdsa_verify_time = time.perf_counter() - start
    
    # Serialize public key to DER format for size calculation
    # DER (Distinguished Encoding Rules) is a binary encoding format
    ecdsa_public_key_bytes = ecdsa_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Store ECDSA results with timing and size metrics
    results['ecdsa'] = {
        'signature': bytes_to_base64(ecdsa_sign),
        'public_key': bytes_to_base64(ecdsa_public_key_bytes),
        'sign_time': round(ecdsa_sign_time * 1000, 3),
        'verify_time': round(ecdsa_verify_time * 1000, 3),
        'signature_size_bytes': len(ecdsa_sign),
        'signature_size_bits': len(ecdsa_sign) * 8,
        'public_key_size_bytes': len(ecdsa_public_key_bytes),
        'public_key_size_bits': len(ecdsa_public_key_bytes) * 8
    }
    
    # Return results as JSON for frontend display
    return jsonify(results)

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    """
    Handle key encapsulation (encryption) comparison between ECDH and ML-KEM.
    
    This endpoint performs two key encapsulation operations:
    1. ML-KEM (Module-Lattice Key Encapsulation Mechanism) - Post-quantum
    2. ECDH (Elliptic Curve Diffie-Hellman) - Classical
    
    Key encapsulation is different from traditional encryption:
    - It's used to securely exchange a shared secret between two parties
    - The sender encapsulates a shared secret using the receiver's public key
    - The receiver decapsulates to obtain the same shared secret
    - This shared secret is then used for symmetric encryption
    
    Returns:
        JSON containing timing and size metrics for both algorithms
    """
    # Get message from form input and encode to bytes (UTF-8)
    message = request.form.get('message', '').encode('utf-8')
    
    # Initialize results dictionary with the original message
    results = {'message': message.decode('utf-8')}
    
    # =================================================================
    # ML-KEM (Module-Lattice Key Encapsulation Mechanism) - Post-Quantum
    # =================================================================
    # ML-KEM is based on the Module-LWE (Learning With Errors) problem
    # It's one of the NIST-standardized post-quantum KEM algorithms
    # 
    # Key Encapsulation Mechanism (KEM) workflow:
    # 1. Receiver generates key pair (ek=encapsulation key, dk=decapsulation key)
    # 2. Sender uses ek to encapsulate (encrypt) a random shared secret
    # 3. Sender sends ciphertext to receiver
    # 4. Receiver uses dk to decapsulate and recover the shared secret
    # 5. Both parties now have the same shared secret
    
    # Generate ML-KEM key pair
    # ek (encapsulation key): public key, shared with sender
    # dk (decapsulation key): private key, kept secret by receiver
    ek, dk = ML_KEM_768.keygen()
    
    # Time the encapsulation operation
    # The sender calls this to create a ciphertext containing the encrypted
    # shared secret, using the receiver's encapsulation key (ek)
    start = time.perf_counter()
    ml_kem_ss, ml_kem_ct = ML_KEM_768.encaps(ek)
    ml_kem_encap_time = time.perf_counter() - start
    
    # Time the decapsulation operation
    # The receiver uses their decapsulation key (dk) and the ciphertext
    # to recover the same shared secret that the sender created
    start = time.perf_counter()
    ml_kem_decap_ss = ML_KEM_768.decaps(dk, ml_kem_ct)
    ml_kem_decap_time = time.perf_counter() - start
    
    # Store ML-KEM results with timing and size metrics
    results['ml_kem'] = {
        'ciphertext': bytes_to_base64(ml_kem_ct),
        'shared_secret': bytes_to_base64(ml_kem_ss),
        'public_key': bytes_to_base64(ek),
        'encap_time': round(ml_kem_encap_time * 1000, 3),
        'decap_time': round(ml_kem_decap_time * 1000, 3),
        'ciphertext_size_bytes': len(ml_kem_ct),
        'ciphertext_size_bits': len(ml_kem_ct) * 8,
        'public_key_size_bytes': len(ek),
        'public_key_size_bits': len(ek) * 8
    }
    
    # =================================================================
    # ECDH (Elliptic Curve Diffie-Hellman) - Classical
    # =================================================================
    # ECDH is based on the elliptic curve discrete logarithm problem
    # It's vulnerable to quantum attacks (Shor's algorithm)
    # 
    # ECDH workflow (Diffie-Hellman key exchange):
    # 1. Alice generates ephemeral key pair (private_a, public_a)
    # 2. Bob generates ephemeral key pair (private_b, public_b)
    # 3. Alice sends public_a to Bob, Bob sends public_b to Alice
    # 4. Alice computes: shared_secret = private_a * public_b
    # 5. Bob computes: shared_secret = private_b * public_a
    # 6. Both arrive at the same shared secret ( ECDH magic! )
    
    # Generate ECDH key pair for the "receiver" (Bob in the example above)
    ecdh_private = ec.generate_private_key(ec.SECP256R1())
    ecdh_public = ecdh_private.public_key()
    
    # Time ephemeral key generation (simulating Alice generating her keys)
    start = time.perf_counter()
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ecdh_keygen_time = time.perf_counter() - start
    
    # Time the key exchange (Alice computing shared secret using Bob's public key)
    # This simulates the encapsulation part of KEM
    start = time.perf_counter()
    ecdh_ss = ephemeral_private.exchange(ec.ECDH(), ecdh_public)
    ecdh_decap_time = time.perf_counter() - start
    
    # Serialize public key to DER format for size calculation
    ecdh_public_key_bytes = ecdh_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Store ECDH results with timing and size metrics
    results['ecdh'] = {
        'shared_secret': bytes_to_base64(ecdh_ss),
        'public_key': bytes_to_base64(ecdh_public_key_bytes),
        'keygen_time': round(ecdh_keygen_time * 1000, 3),
        'key_exchange_time': round(ecdh_decap_time * 1000, 3),
        'public_key_size_bytes': len(ecdh_public_key_bytes),
        'public_key_size_bits': len(ecdh_public_key_bytes) * 8
    }
    
    # Return results as JSON for frontend display
    return jsonify(results)


if __name__ == '__main__':
    # Run the Flask development server
    # debug=True enables auto-reload on code changes and detailed error pages
    # In production, debug should be False and a proper WSGI server should be used
    app.run(debug=True)
