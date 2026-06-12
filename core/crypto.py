from flask import Blueprint, request
from core.utils import success, error
import math
import sympy
from sympy.ntheory.factor_ import factorint
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import base64
import hashlib

crypto_bp = Blueprint('crypto', __name__)


# -- RSA LARGE FACTOR ----------------------------------------------------------
@crypto_bp.route('/rsa/factor', methods=['POST'])
def rsa_factor():
    """Factor RSA modulus N using sympy."""
    data = request.json or {}
    n_str = data.get('n', '').strip()
    if not n_str:
        return error('Provide modulus n')
    try:
        n = int(n_str)
        if n < 4:
            return error('N must be >= 4')
        factors = factorint(n)
        primes  = list(factors.keys())

        result = {
            'n':       str(n),
            'factors': {str(k): v for k, v in factors.items()},
            'primes':  [str(p) for p in primes],
        }

        if len(primes) == 2:
            p, q = primes[0], primes[1]
            phi  = (p - 1) * (q - 1)
            result['p']   = str(p)
            result['q']   = str(q)
            result['phi'] = str(phi)

        return success(result)
    except Exception as e:
        return error(f'Factoring failed: {str(e)}')


# -- RSA WIENER ATTACK ---------------------------------------------------------
@crypto_bp.route('/rsa/wiener', methods=['POST'])
def rsa_wiener():
    """RSA Wiener attack for small private exponent d."""
    data  = request.json or {}
    e_str = data.get('e', '').strip()
    n_str = data.get('n', '').strip()
    if not e_str or not n_str:
        return error('Provide e and n')

    try:
        e = int(e_str)
        n = int(n_str)

        def continued_fraction(num, den):
            fracs = []
            while den:
                fracs.append(num // den)
                num, den = den, num % den
            return fracs

        def convergents(cf):
            convs = []
            for i in range(len(cf)):
                if i == 0:
                    convs.append((cf[0], 1))
                elif i == 1:
                    convs.append((cf[1]*cf[0]+1, cf[1]))
                else:
                    h = cf[i]*convs[i-1][0] + convs[i-2][0]
                    k = cf[i]*convs[i-1][1] + convs[i-2][1]
                    convs.append((h, k))
            return convs

        cf   = continued_fraction(e, n)
        convs = convergents(cf)

        for k, d in convs:
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            # Check if phi gives valid p,q
            b = n - phi + 1
            discriminant = b*b - 4*n
            if discriminant < 0:
                continue
            sqrt_disc = math.isqrt(discriminant)
            if sqrt_disc * sqrt_disc != discriminant:
                continue
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            if p * q == n:
                return success({
                    'vulnerable': True,
                    'p':   str(p),
                    'q':   str(q),
                    'd':   str(d),
                    'phi': str(phi),
                    'message': 'Wiener attack successful! Private key recovered.'
                })

        return success({
            'vulnerable': False,
            'message':    'Wiener attack failed - d is likely not small enough.'
        })

    except Exception as e:
        return error(f'Wiener attack error: {str(e)}')


# -- RSA DECRYPT WITH PQ -------------------------------------------------------
@crypto_bp.route('/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    """Decrypt RSA ciphertext given p, q, e, c."""
    data  = request.json or {}
    try:
        p = int(data.get('p', 0))
        q = int(data.get('q', 0))
        e = int(data.get('e', 65537))
        c = int(data.get('c', 0))

        n   = p * q
        phi = (p - 1) * (q - 1)
        d   = pow(e, -1, phi)
        m   = pow(c, d, n)

        m_bytes = long_to_bytes(m)
        try:
            plaintext = m_bytes.decode('utf-8')
        except Exception:
            plaintext = m_bytes.decode('latin-1', errors='replace')

        return success({
            'n':         str(n),
            'phi':       str(phi),
            'd':         str(d),
            'm_int':     str(m),
            'plaintext': plaintext,
            'm_hex':     m_bytes.hex(),
        })
    except Exception as ex:
        return error(f'Decryption error: {str(ex)}')


# -- RSA HASTAD BROADCAST ATTACK -----------------------------------------------
@crypto_bp.route('/rsa/hastad', methods=['POST'])
def rsa_hastad():
    """RSA Hastad broadcast attack for e=3."""
    data = request.json or {}
    try:
        ciphertexts = data.get('ciphertexts', [])
        moduli      = data.get('moduli', [])
        e           = int(data.get('e', 3))

        if len(ciphertexts) < e or len(moduli) < e:
            return error(f'Need at least {e} ciphertext/modulus pairs for e={e}')

        c_list = [int(c) for c in ciphertexts[:e]]
        n_list = [int(n) for n in moduli[:e]]

        # CRT
        def crt(remainders, moduli):
            M    = 1
            for m in moduli: M *= m
            result = 0
            for r, m in zip(remainders, moduli):
                Mi   = M // m
                inv  = pow(Mi, -1, m)
                result += r * Mi * inv
            return result % M

        x   = crt(c_list, n_list)
        m   = sympy.integer_nthroot(x, e)[0]

        m_bytes = long_to_bytes(m)
        try:
            plaintext = m_bytes.decode('utf-8')
        except Exception:
            plaintext = m_bytes.decode('latin-1', errors='replace')

        return success({
            'message':   str(m),
            'plaintext': plaintext,
            'hex':       m_bytes.hex(),
        })
    except Exception as ex:
        return error(f'Hastad attack error: {str(ex)}')


# -- RSA KEY PARSER ------------------------------------------------------------
@crypto_bp.route('/rsa/parse_key', methods=['POST'])
def rsa_parse_key():
    """Parse RSA public/private key PEM."""
    data    = request.json or {}
    pem_str = data.get('pem', '').strip()
    if not pem_str:
        return error('Provide PEM key')
    try:
        key = RSA.import_key(pem_str)
        result = {
            'n':        str(key.n),
            'e':        str(key.e),
            'key_size': key.size_in_bits(),
            'has_private': key.has_private(),
        }
        if key.has_private():
            result['d'] = str(key.d)
            result['p'] = str(key.p)
            result['q'] = str(key.q)
        return success(result)
    except Exception as ex:
        return error(f'Key parse error: {str(ex)}')


# -- HASH CRACKER (server-side) ------------------------------------------------
@crypto_bp.route('/hash/crack', methods=['POST'])
def hash_crack():
    """Crack hash using server-side wordlist."""
    data     = request.json or {}
    hash_val = data.get('hash', '').strip().lower()
    wordlist = data.get('wordlist', [])
    algos    = ['md5', 'sha1', 'sha256', 'sha512', 'sha224', 'sha384']

    if not hash_val:
        return error('Provide a hash')
    if not wordlist:
        return error('Provide a wordlist array')
    if len(wordlist) > 100000:
        return error('Wordlist too large (max 100,000 words)')

    for word in wordlist:
        word = str(word).strip()
        for algo in algos:
            try:
                h = hashlib.new(algo)
                h.update(word.encode())
                if h.hexdigest() == hash_val:
                    return success({
                        'found':     True,
                        'plaintext': word,
                        'algorithm': algo.upper(),
                    })
            except Exception:
                pass

    return success({ 'found': False, 'message': 'Not found in provided wordlist' })


# -- AES ENCRYPT / DECRYPT -----------------------------------------------------
@crypto_bp.route('/aes', methods=['POST'])
def aes_operation():
    """AES encrypt/decrypt with proper padding."""
    data   = request.json or {}
    mode   = data.get('mode', 'enc')
    text   = data.get('text', '')
    key    = data.get('key', '')
    aes_mode = data.get('aes_mode', 'CBC')

    if not text or not key:
        return error('Provide text and key')

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad

        key_bytes = hashlib.sha256(key.encode()).digest()[:16]
        iv        = b'\x00' * 16

        mode_map = {
            'CBC': AES.MODE_CBC,
            'ECB': AES.MODE_ECB,
            'CTR': AES.MODE_CTR,
            'CFB': AES.MODE_CFB,
        }
        aes_mode_val = mode_map.get(aes_mode, AES.MODE_CBC)

        if mode == 'enc':
            if aes_mode_val == AES.MODE_ECB:
                cipher    = AES.new(key_bytes, AES.MODE_ECB)
                encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
            elif aes_mode_val == AES.MODE_CTR:
                cipher    = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8)
                encrypted = cipher.encrypt(text.encode())
            else:
                cipher    = AES.new(key_bytes, aes_mode_val, iv=iv)
                encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
            return success({
                'result': base64.b64encode(encrypted).decode(),
                'hex':    encrypted.hex(),
            })
        else:
            ct = base64.b64decode(text)
            if aes_mode_val == AES.MODE_ECB:
                cipher    = AES.new(key_bytes, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(ct), AES.block_size)
            elif aes_mode_val == AES.MODE_CTR:
                cipher    = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8)
                decrypted = cipher.decrypt(ct)
            else:
                cipher    = AES.new(key_bytes, aes_mode_val, iv=iv)
                decrypted = unpad(cipher.decrypt(ct), AES.block_size)
            return success({ 'result': decrypted.decode('utf-8', errors='replace') })

    except Exception as ex:
        return error(f'AES error: {str(ex)}')
