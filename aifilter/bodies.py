"""Bounded decoded prefixes without mitmproxy's whole-body decoding cache.

Uses the compression implementations already shipped with mitmproxy. Call in a
worker thread: a compressed body never monopolizes the proxy event loop.
"""
import zlib

MAX_COMPRESSED_BYTES = 1_048_576
MAX_MEMBERS = 32


def prefix(raw, encoding, limit, max_compressed=MAX_COMPRESSED_BYTES):
    raw = raw or b''
    encoding = encoding.lower().strip()
    if encoding in ('', 'identity', 'none'):
        return raw[:limit], len(raw) <= limit
    input_complete = len(raw) <= max_compressed
    raw = raw[:max_compressed]
    output = bytearray()
    try:
        if encoding in ('gzip', 'deflate', 'deflateraw'):
            windows = 31 if encoding == 'gzip' else (-15 if encoding == 'deflateraw' else 15)
            output = bytearray()
            remaining = raw
            members = 0
            while remaining:
                if members >= MAX_MEMBERS:
                    return bytes(output), False
                members += 1
                decoder = zlib.decompressobj(windows)
                try:
                    part = decoder.decompress(remaining, limit + 1 - len(output))
                except zlib.error:
                    if encoding != 'deflate' or windows == -15:
                        raise
                    windows = -15
                    decoder = zlib.decompressobj(windows)
                    part = decoder.decompress(remaining, limit + 1 - len(output))
                output.extend(part)
                if len(output) > limit:
                    return bytes(output[:limit]), False
                if not decoder.eof:
                    return bytes(output), False
                remaining = decoder.unused_data
                if encoding == "gzip":
                    remaining = remaining.lstrip(b"\0")
                # gzip permits concatenated members; never stop after an empty member.
            return bytes(output), input_complete
        if encoding == 'br':
            import brotli
            decoder = brotli.Decompressor()
            data = decoder.process(raw, output_buffer_limit=limit + 1)
            return data[:limit], input_complete and decoder.is_finished() and len(data) <= limit
        if encoding == 'zstd':
            from mitmproxy.net.encoding import zstd
            output = bytearray()
            remaining = raw
            members = 0
            while remaining:
                if members >= MAX_MEMBERS:
                    return bytes(output), False
                members += 1
                decoder = zstd.ZstdDecompressor()
                output.extend(decoder.decompress(remaining, max_length=limit + 1 - len(output)))
                if len(output) > limit:
                    return bytes(output[:limit]), False
                if not decoder.eof:
                    return bytes(output), False
                remaining = decoder.unused_data
            return bytes(output), input_complete
    except Exception:
        # Broken/unsupported encoding: leave the original response untouched.
        return bytes(output[:limit]), False
    return b'', False


def replace_spans(data, replacements):
    chunks, cursor = [], 0
    for start, end, replacement in replacements:
        chunks.extend((data[cursor:start], replacement))
        cursor = end
    chunks.append(data[cursor:])
    return b''.join(chunks)
