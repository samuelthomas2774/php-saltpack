<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;
use MessagePack\PackOptions;
use BadMethodCallException;
use InvalidArgumentException;
use UnexpectedValueException;

// [
//     signcrypted chunk,
//     final flag,
// ]

class SigncryptedMessagePayload
{
    const PAYLOAD_NONCE_PREFIX = 'saltpack_ploadsb';

    /** @var string $payload_secretbox */
    protected $payload_secretbox;

    /** @var bool $final */
    protected $final;

    /** @var string $encoded_data */
    protected $encoded_data = null;

    public function __construct(string $payload_secretbox, bool $final)
    {
        $this->payload_secretbox = $payload_secretbox;
        $this->final = $final;
    }

    public function __get(string $key)
    {
        if ($key === 'payload_secretbox') return $this->payload_secretbox;
        if ($key === 'final') return $this->final;

        if (!isset($this->encoded_data) && $key === 'encoded') {
            $this->encoded_data = $this->encode();
        }

        if ($key === 'encoded') return $this->encoded_data;

        throw new BadMethodCallException('Unknown property "' . $key . '"');
    }

    public function __debugInfo()
    {
        return [
            'payload_secretbox' => $this->payload_secretbox,
            'final' => $this->final,
        ];
    }

    public static function create(
        SigncryptedMessageHeader $header, string $payload_key, ?string $private_key,
        string $data, int $index, bool $final = false
    ): SigncryptedMessagePayload
    {
        $nonce = self::generateNonce($header->hash, $index, $final);

        // 3. Sign the signature input with the sender's long-term private signing key, producing a 64-byte
        // Ed25519 signature. If the sender is anonymous, the signature is 64 zero bytes instead.
        $signature = $private_key ? sodium_crypto_sign_detached(
            self::generateSignatureData($header->hash, $nonce, $final, $data), $private_key
        ) : str_repeat("\0", 64);

        // 4. Prepend that signature onto the front of the plaintext chunk.
        // 5. Encrypt the attached signature from #4 using the payload key and the packet nonce.

        $payload_secretbox = sodium_crypto_secretbox(
            $signature . $data, $nonce, $payload_key
        );

        return new self($payload_secretbox, $final);
    }

    public static function generateNonce(string $header_hash, int $index, bool $final): string
    {
        // 1. Compute the packet nonce. Take the first 16 bytes of the header hash. If this is the final packet,
        // set the least significant bit of the last of those bytes to one (nonce[15] |= 0x01), otherwise set it
        // to zero (nonce[15] &= 0xfe). Finally, append the 8-byte unsigned big-endian packet number, where the
        // first payload packet is zero.

        $nonce = substr($header_hash, 0, 16);
        $nonce[15] = chr($final ? ord($nonce[15]) | 0x01 : ord($nonce[15]) & 0xfe);
        $nonce .= pack('J', $index);

        return $nonce;
    }

    public static function generateSignatureData(
        string $header_hash, string $nonce, bool $final, string $data
    ): string
    {
        // 2. Concatenate several values to form the signature input:
        //     - the constant string saltpack encrypted signature
        //     - a null byte, 0x00
        //     - the header hash
        //     - the packet nonce computed above
        //     - the final flag byte, 0x00 for false and 0x01 for true
        //     - the SHA512 hash of the plaintext

        return 'saltpack encrypted signature' .
            "\x00" .
            $header_hash .
            $nonce .
            ($final ? "\x01" : "\x00") .
            hash('sha512', $data, true);
    }

    public function encode()
    {
        return self::encodePayload($this->payload_secretbox, $this->final);
    }

    public static function encodePayload(string $payload_secretbox, bool $final): string
    {
        $data = [
            $payload_secretbox,
            $final,
        ];

        return MessagePack::pack($data, PackOptions::FORCE_BIN);
    }

    public static function decode($encoded, $unpacked = false): SigncryptedMessagePayload
    {
        $data = $unpacked ? $encoded : MessagePack::unpack($encoded);

        if (count($data) < 2) throw new UnexpectedValueException('Invalid data');

        list($payload_secretbox, $final) = $data;

        return new self($payload_secretbox, $final);
    }

    public function decrypt(
        SigncryptedMessageHeader $header, ?string $public_key, string $payload_key, int $index
    ): string
    {
        // 1. Compute the packet nonce as above.
        $nonce = self::generateNonce($header->hash, $index, $this->final);

        // 2. Decrypt the chunk using the payload key and the packet nonce.
        $signature_data = sodium_crypto_secretbox_open($this->payload_secretbox, $nonce, $payload_key);

        if ($signature_data === false) {
            throw new Exceptions\DecryptionError('Failed to decrypt data');
        }

        // 3. Take the first 64 bytes of the plaintext as the detached signature, and the rest as the payload chunk.
        $data = substr($signature_data, 64);

        if ($public_key !== null) {
            $signature = substr($signature_data, 0, 64);

            // 4. Compute the signature input as above.
            $sign_data = self::generateSignatureData($header->hash, $nonce, $this->final, $data);

            // 5. Verify the detached signature from step #3 against the signature input. If the sender's public key
            // is all zero bytes, however, then the sender is anonymous, and verification is skipped.
            if (!sodium_crypto_sign_verify_detached($signature, $sign_data, $public_key)) {
                throw new Exceptions\VerifyError('Invalid signature');
            }
        }

        // 6. If the signature was valid, output the payload chunk.
        return $data;
    }
}
