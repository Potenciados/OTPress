<?php
defined('ABSPATH') || exit;

/**
 * Minimal CBOR (RFC 8949) decoder — just enough to walk a WebAuthn
 * attestationObject and the COSE public key nested inside its
 * attestedCredentialData.
 *
 * No Composer dependency and no extension required: only the major types the
 * authenticator emits are handled — unsigned/negative integers, byte strings,
 * text strings, arrays, maps and tags. Floats, indefinite-length items and
 * anything else raise a decode error rather than being silently mis-parsed.
 *
 * The public entry point is decode_first(): it returns the first decoded value
 * together with the byte offset just past it, so a caller can tell how much of
 * the buffer the item consumed (the attestationObject is a map whose authData
 * byte string then carries its own trailing COSE key to decode separately).
 */
class OTPress_CBOR {

    /**
     * Decode a single CBOR data item from the front of $bytes.
     *
     * @param string $bytes Raw CBOR.
     * @return array{0:mixed,1:int} [decoded value, offset past the item].
     * @throws Exception on malformed / unsupported input.
     */
    public static function decode_first(string $bytes): array {
        return self::decode_item($bytes, 0);
    }

    /**
     * Decode the whole buffer, requiring it to contain exactly one item.
     *
     * @return mixed
     * @throws Exception
     */
    public static function decode(string $bytes) {
        [$value, $offset] = self::decode_item($bytes, 0);
        if ($offset !== strlen($bytes)) {
            throw new Exception('CBOR: trailing bytes after value.');
        }
        return $value;
    }

    /**
     * @return array{0:mixed,1:int}
     * @throws Exception
     */
    private static function decode_item(string $bytes, int $offset): array {
        if ($offset >= strlen($bytes)) {
            throw new Exception('CBOR: unexpected end of input.');
        }

        $ib    = ord($bytes[$offset]);
        $major = $ib >> 5;
        $minor = $ib & 0x1F;
        $offset++;

        // Additional-information / argument.
        [$arg, $offset] = self::read_argument($bytes, $offset, $minor);

        switch ($major) {
            case 0: // unsigned integer
                return [$arg, $offset];

            case 1: // negative integer: -1 - arg
                return [-1 - $arg, $offset];

            case 2: // byte string
                return self::read_bytes($bytes, $offset, $arg);

            case 3: // text string
                [$str, $offset] = self::read_bytes($bytes, $offset, $arg);
                return [$str, $offset];

            case 4: // array
                $arr = [];
                for ($i = 0; $i < $arg; $i++) {
                    [$val, $offset] = self::decode_item($bytes, $offset);
                    $arr[] = $val;
                }
                return [$arr, $offset];

            case 5: // map
                $map = [];
                for ($i = 0; $i < $arg; $i++) {
                    [$key, $offset] = self::decode_item($bytes, $offset);
                    [$val, $offset] = self::decode_item($bytes, $offset);
                    if (!is_int($key) && !is_string($key)) {
                        throw new Exception('CBOR: unsupported map key type.');
                    }
                    $map[$key] = $val;
                }
                return [$map, $offset];

            case 6: // tag: decode and return the tagged value verbatim
                return self::decode_item($bytes, $offset);

            default:
                throw new Exception('CBOR: unsupported major type ' . $major . '.');
        }
    }

    /**
     * Read the integer argument encoded by the minor value (0..27). Indefinite
     * lengths (31) and reserved values are rejected.
     *
     * @return array{0:int,1:int}
     * @throws Exception
     */
    private static function read_argument(string $bytes, int $offset, int $minor): array {
        if ($minor < 24) {
            return [$minor, $offset];
        }
        $len = match ($minor) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw new Exception('CBOR: unsupported additional info ' . $minor . '.'),
        };
        if ($offset + $len > strlen($bytes)) {
            throw new Exception('CBOR: truncated argument.');
        }
        $value = 0;
        for ($i = 0; $i < $len; $i++) {
            $value = ($value << 8) | ord($bytes[$offset + $i]);
        }
        // 64-bit lengths that overflow PHP's signed int would be nonsensical
        // for an authenticator payload; guard against a negative wrap.
        if ($value < 0) {
            throw new Exception('CBOR: argument out of range.');
        }
        return [$value, $offset + $len];
    }

    /**
     * @return array{0:string,1:int}
     * @throws Exception
     */
    private static function read_bytes(string $bytes, int $offset, int $length): array {
        if ($offset + $length > strlen($bytes)) {
            throw new Exception('CBOR: truncated string.');
        }
        return [substr($bytes, $offset, $length), $offset + $length];
    }
}
