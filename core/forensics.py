from flask import Blueprint, request
from core.utils import success, error, safe_decode
import os
import io
import base64
import hashlib
import zipfile
import struct
import math

forensics_bp = Blueprint('forensics', __name__)

UPLOAD_FOLDER = 'uploads'


# -- FILE UPLOAD HELPER --------------------------------------------------------
def get_uploaded_file():
    if 'file' not in request.files:
        return None, error('No file uploaded')
    f = request.files['file']
    if f.filename == '':
        return None, error('No file selected')
    data = f.read()
    return data, None


# -- FILE ANALYSIS -------------------------------------------------------------
@forensics_bp.route('/analyze', methods=['POST'])
def analyze_file():
    """Full file analysis - magic bytes, entropy, strings, hashes."""
    data, err = get_uploaded_file()
    if err:
        return err

    # Hashes
    hashes = {
        'md5':    hashlib.md5(data).hexdigest(),
        'sha1':   hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha512': hashlib.sha512(data).hexdigest(),
    }

    # Entropy
    freq    = [0] * 256
    for b in data: freq[b] += 1
    n       = len(data)
    if n == 0:
        return error('Uploaded file is empty')
    entropy = 0.0
    for f in freq:
        if f > 0:
            p        = f / n
            entropy -= p * math.log2(p)

    # Magic bytes detection
    file_type = detect_magic(data)

    # Extract strings
    strings = extract_strings(data, min_len=4)

    # Hex preview (first 256 bytes)
    hex_preview = format_hex_dump(data[:256])

    return success({
        'filename':    request.files['file'].filename,
        'size':        len(data),
        'hashes':      hashes,
        'entropy':     round(entropy, 4),
        'file_type':   file_type,
        'strings':     strings[:200],  # limit
        'string_count':len(strings),
        'hex_preview': hex_preview,
        'is_text':     entropy < 5.0,
        'is_encrypted':entropy > 7.5,
    })


# -- STRINGS EXTRACTOR ---------------------------------------------------------
@forensics_bp.route('/strings', methods=['POST'])
def extract_strings_route():
    """Extract all printable strings from binary file."""
    data, err = get_uploaded_file()
    if err:
        return err

    min_len   = int(request.form.get('min_len', 4))
    filter_kw = request.form.get('filter', '').lower()
    strings   = extract_strings(data, min_len=min_len)

    if filter_kw:
        strings = [s for s in strings if filter_kw in s.lower()]

    return success({
        'total':   len(strings),
        'strings': strings[:2000],
        'filter':  filter_kw,
    })


def extract_strings(data, min_len=4):
    strings  = []
    current  = ''
    for b in data:
        if 0x20 <= b < 0x7f:
            current += chr(b)
        else:
            if len(current) >= min_len:
                strings.append(current)
            current = ''
    if len(current) >= min_len:
        strings.append(current)
    return strings


# -- HEX DUMP ------------------------------------------------------------------
@forensics_bp.route('/hexdump', methods=['POST'])
def hex_dump_route():
    """Generate full hex dump of uploaded file."""
    data, err = get_uploaded_file()
    if err:
        return err

    max_bytes = int(request.form.get('max_bytes', 4096))
    chunk     = data if max_bytes <= 0 else data[:max_bytes]
    dump      = format_hex_dump(chunk)

    return success({
        'total_size':   len(data),
        'shown_bytes':  len(chunk),
        'hex_dump':     dump,
        'truncated':    max_bytes > 0 and len(data) > max_bytes,
    })


def format_hex_dump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk   = data[i:i+16]
        offset  = f'{i:08x}'
        hex_str = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_  = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f'{offset}  {hex_str}  |{ascii_}|')
    return '\n'.join(lines)


# -- MAGIC BYTES DETECTOR ------------------------------------------------------
@forensics_bp.route('/magic', methods=['POST'])
def magic_bytes_route():
    """Identify file type from magic bytes."""
    data, err = get_uploaded_file()
    if err:
        return err

    result = detect_magic(data)
    hex_bytes = ' '.join(f'{b:02x}' for b in data[:16])

    return success({
        'file_type':  result,
        'first_bytes':hex_bytes,
        'filename':   request.files['file'].filename,
    })


def detect_magic(data):
    if len(data) < 4:
        return 'Unknown (too small)'

    signatures = [
        (b'\x89PNG\r\n\x1a\n',          'PNG Image'),
        (b'\xff\xd8\xff',                'JPEG Image'),
        (b'GIF8',                         'GIF Image'),
        (b'BM',                           'BMP Image'),
        (b'%PDF',                         'PDF Document'),
        (b'PK\x03\x04',                   'ZIP Archive'),
        (b'Rar!\x1a\x07',                 'RAR Archive'),
        (b'\x1f\x8b\x08',                 'GZIP Archive'),
        (b'BZh',                           'BZIP2 Archive'),
        (b'\xfd7zXZ\x00',                  'XZ Archive'),
        (b'\x7fELF',                       'ELF Binary'),
        (b'MZ',                            'Windows PE/EXE'),
        (b'\xca\xfe\xba\xbe',              'Java Class File'),
        (b'\xce\xfa\xed\xfe',              'Mach-O 32-bit'),
        (b'\xcf\xfa\xed\xfe',              'Mach-O 64-bit'),
        (b'RIFF',                           'WAV/AVI'),
        (b'\x00\x00\x00\x18ftyp',           'MP4 Video'),
        (b'SQLite format 3\x00',            'SQLite Database'),
        (b'#!',                             'Script/Shebang'),
        (b'OggS',                           'OGG Audio'),
        (b'ID3',                            'MP3 Audio'),
        (b'\x49\x49\x2a\x00',              'TIFF (Little Endian)'),
        (b'\x4d\x4d\x00\x2a',              'TIFF (Big Endian)'),
        (b'IHDR',                           'PNG Chunk'),
        (b'-----BEGIN',                     'PEM Certificate/Key'),
        (b'<?xml',                          'XML Document'),
        (b'<html',                          'HTML Document'),
        (b'{',                              'JSON (possible)'),
    ]

    for sig, name in signatures:
        if data[:len(sig)] == sig:
            return name

    # Check if text
    try:
        data[:512].decode('utf-8')
        return 'Text/ASCII'
    except Exception:
        pass

    return 'Unknown Binary'


# -- PNG CHUNK ANALYZER --------------------------------------------------------
@forensics_bp.route('/png_chunks', methods=['POST'])
def png_chunks():
    """Analyze PNG file chunks."""
    data, err = get_uploaded_file()
    if err:
        return err

    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return error('Not a valid PNG file')

    chunks  = []
    offset  = 8
    while offset < len(data) - 12:
        try:
            length = struct.unpack('>I', data[offset:offset+4])[0]
            ctype  = data[offset+4:offset+8].decode('ascii', errors='replace')
            cdata  = data[offset+8:offset+8+length]
            crc    = struct.unpack('>I', data[offset+8+length:offset+12+length])[0]

            preview = ''
            if ctype in ('tEXt', 'iTXt', 'zTXt'):
                try:
                    preview = cdata.decode('utf-8', errors='replace').replace('\x00', ' | ')
                except Exception:
                    pass

            chunks.append({
                'type':    ctype,
                'length':  length,
                'offset':  offset,
                'crc':     hex(crc),
                'preview': preview[:200],
                'hex':     cdata[:16].hex() + ('...' if len(cdata) > 16 else ''),
            })
            offset += 12 + length
            if ctype == 'IEND':
                break
        except Exception:
            break

    return success({
        'valid': True,
        'chunks': chunks,
        'total':  len(chunks),
    })


# -- ENTROPY ANALYSIS ----------------------------------------------------------
@forensics_bp.route('/entropy', methods=['POST'])
def entropy_analysis():
    """Calculate Shannon entropy and byte frequency."""
    data, err = get_uploaded_file()
    if err:
        return err

    freq    = [0] * 256
    for b in data: freq[b] += 1
    n       = len(data)
    if n == 0:
        return error('Uploaded file is empty')
    entropy = 0.0
    for f in freq:
        if f > 0:
            p        = f / n
            entropy -= p * math.log2(p)

    # Top bytes
    top_bytes = sorted(
        [{ 'byte': i, 'hex': hex(i), 'count': freq[i], 'pct': round(freq[i]/n*100, 2) }
         for i in range(256) if freq[i] > 0],
        key=lambda x: x['count'], reverse=True
    )[:20]

    interpretation = (
        'Very high - likely encrypted or compressed' if entropy > 7.5
        else 'High - possibly compressed or binary' if entropy > 6.5
        else 'Medium - mixed data' if entropy > 4.5
        else 'Low - likely plain text or structured data'
    )

    return success({
        'entropy':        round(entropy, 6),
        'max_entropy':    8.0,
        'interpretation': interpretation,
        'file_size':      n,
        'unique_bytes':   sum(1 for f in freq if f > 0),
        'null_bytes':     freq[0],
        'top_bytes':      top_bytes,
    })


# -- ZIP PASSWORD CRACKER ------------------------------------------------------
@forensics_bp.route('/zip_crack', methods=['POST'])
def zip_crack():
    """Crack ZIP file password using provided wordlist."""
    if 'file' not in request.files:
        return error('No ZIP file uploaded')

    wordlist_raw = request.form.get('wordlist', '')
    if not wordlist_raw:
        return error('Provide a wordlist (newline separated)')

    zip_data = request.files['file'].read()
    words    = [w.strip() for w in wordlist_raw.split('\n') if w.strip()]

    if len(words) > 50000:
        return error('Wordlist too large (max 50,000 words)')

    try:
        import pyzipper
        zf = pyzipper.AESZipFile(io.BytesIO(zip_data))

        names = zf.namelist()
        if not names:
            return error('ZIP archive is empty')

        # Test passwords by reading the first file instead of extracting files.
        try:
            zf.read(names[0], pwd=b'')
            return success({ 'protected': False, 'message': 'ZIP is not password protected' })
        except Exception:
            pass

        for word in words:
            try:
                zf.read(names[0], pwd=word.encode('utf-8'))
                return success({
                    'found':    True,
                    'password': word,
                    'tried':    words.index(word) + 1,
                })
            except Exception:
                pass

        return success({
            'found':   False,
            'tried':   len(words),
            'message': 'Password not found in wordlist',
        })

    except Exception as ex:
        # Fallback to standard zipfile
        try:
            zf = zipfile.ZipFile(io.BytesIO(zip_data))
            names = zf.namelist()
            if not names:
                return error('ZIP archive is empty')
            for word in words:
                try:
                    zf.read(names[0], pwd=word.encode())
                    return success({ 'found': True, 'password': word })
                except Exception:
                    pass
            return success({ 'found': False, 'tried': len(words) })
        except Exception as ex2:
            return error(f'ZIP crack error: {str(ex2)}')


# -- LSB STEGANOGRAPHY ---------------------------------------------------------
@forensics_bp.route('/lsb', methods=['POST'])
def lsb_extract():
    """Extract LSB steganography from image (server-side with Pillow)."""
    data, err = get_uploaded_file()
    if err:
        return err

    bits_per_channel = int(request.form.get('bits', 1))

    try:
        from PIL import Image
        img    = Image.open(io.BytesIO(data)).convert('RGB')
        pixels = list(img.getdata())

        mask   = (1 << bits_per_channel) - 1
        bits   = ''

        for r, g, b in pixels:
            bits += format(r & mask, f'0{bits_per_channel}b')
            bits += format(g & mask, f'0{bits_per_channel}b')
            bits += format(b & mask, f'0{bits_per_channel}b')

        # Convert to bytes
        byte_arr = []
        for i in range(0, len(bits) - 8, 8):
            byte_arr.append(int(bits[i:i+8], 2))

        # Find null terminator
        text = ''
        for b in byte_arr:
            if b == 0:
                break
            if 0x20 <= b < 0x7f:
                text += chr(b)
            elif text:
                text += '.'

        hex_preview = ' '.join(f'{b:02x}' for b in byte_arr[:32])

        has_flag   = any(p in text.lower() for p in ['flag{', 'ctf{', 'htb{'])
        printable  = sum(1 for b in byte_arr[:1000] if 0x20 <= b < 0x7f)
        sample_size = min(len(byte_arr), 1000) or 1
        p_ratio    = printable / sample_size

        return success({
            'image_size':      f'{img.width}x{img.height}',
            'bits_per_channel': bits_per_channel,
            'extracted_text':  text[:500],
            'hex_preview':     hex_preview,
            'printable_ratio': round(p_ratio, 3),
            'has_flag':        has_flag,
            'total_bytes':     len(byte_arr),
        })

    except ImportError:
        return error('Pillow not installed. Run: pip install Pillow')
    except Exception as ex:
        return error(f'LSB extraction failed: {str(ex)}')
