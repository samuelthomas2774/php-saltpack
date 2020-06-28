<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;

// [
//     final flag,
//     authenticators list,
//     payload secretbox,
// ]

class EncryptedMessagePayload
{
    const PAYLOAD_NONCE_PREFIX = 'saltpack_ploadsb';

    /** @var bool $final */
    protected $final;

    /** @var string[] $authenticators */
    protected $authenticators;

    /** @var string $payload_secretbox */
    protected $payload_secretbox;

    /** @var string $encoded_data */
    protected $encoded_data = null;

    public function __construct(bool $final, array $authenticators, string $payload_secretbox)
    {
        $this->final = $final;
        $this->authenticators = $authenticators;
        $this->payload_secretbox = $payload_secretbox;
    }

    public function __get(string $key)
    {
        if ($key === 'final') return $this->final;
        if ($key === 'authenticators') return $this->authenticators;
        if ($key === 'payload_secretbox') return $this->payload_secretbox;

        if (!isset($this->encoded_data) && $key === 'encoded') {
            $this->encoded_data = $this->encode();
        }

        if ($key === 'encoded') return $this->encoded_data;

        throw new \Exception('Unknown property "' . $key . '"');
    }

    public static function create(
        EncryptedMessageHeader $header, string $payload_key, string $data, int $index, bool $final = false
    ): EncryptedMessagePayload
    {
        $nonce = self::PAYLOAD_NONCE_PREFIX . pack('J', $index);

        $payload_secretbox = sodium_crypto_secretbox($data, $nonce, $payload_key);

        $authenticator_hash = self::generateAuthenticatorHash($header->hash, $payload_secretbox, $nonce, $final);

        return new EncryptedMessagePayload($final, array_map(function (
            EncryptedMessageRecipient $recipient
        ) use ($authenticator_hash) {
            if ($recipient->mac_key === null) {
                throw new \InvalidArgumentException('Recipient #' . $index . ' doesn\'t have a MAC key set');
            }

            // 3. For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash
            // from #2, using that recipient's MAC key.
            return substr(sodium_crypto_auth($authenticator_hash, $recipient->mac_key), 0, 32);
        }, $header->recipients), $payload_secretbox);
    }

    public static function generateAuthenticatorHash(
        string $header_hash, string $payload_secretbox, string $payload_secretbox_nonce, bool $final
    ): string
    {
        // 1. Concatenate the header hash, the nonce for the payload secretbox, the final flag byte (0x00 or 0x01),
        // and the payload secretbox itself.
        // 2. Compute the crypto_hash (SHA512) of the bytes from #1.
        return hash('sha512',
            $header_hash . $payload_secretbox_nonce . ($final ? "\x01" : "\x00") . $payload_secretbox, true);
    }

    public function encode()
    {
        return self::encodePayload(
            $this->final, $this->authenticators, $this->payload_secretbox
        );
    }

    /**
     * @param int $mode
     * @param string $public_key
     * @param string $sender
     * @param string[] $authenticators
     * @return [string, string]
     */
    public static function encodePayload(
        bool $final, array $authenticators, string $payload_secretbox
    ): string
    {
        $data = [
            $final,
            $authenticators,
            $payload_secretbox,
        ];

        return MessagePack::pack($data);
    }

    public static function decode($encoded, $unpacked = false): EncryptedMessagePayload
    {
        $data = $unpacked ? $encoded : MessagePack::unpack($encoded);

        if (count($data) < 3) throw new \Exception('Invalid data');

        list($final, $authenticators, $payload_secretbox) = $data;

        return new self($final, $authenticators, $payload_secretbox);
    }

    public function decrypt(
        EncryptedMessageHeader $header, EncryptedMessageRecipient $recipient, string $payload_key, int $index
    )
    {
        if ($recipient->mac_key === null) {
            throw new \InvalidArgumentException('Recipient doesn\'t have a MAC key set');
        }

        $authenticator = $this->authenticators[$recipient->index];

        $nonce = self::PAYLOAD_NONCE_PREFIX . pack('J', $index);
        $authenticator_hash = self::generateAuthenticatorHash(
            $header->hash, $this->payload_secretbox, $nonce, $this->final
        );

        // 3. For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash
        // from #2, using that recipient's MAC key.
        $our_authenticator = substr(sodium_crypto_auth($authenticator_hash, $recipient->mac_key), 0, 32);

        if ($authenticator !== $our_authenticator) {
            throw new \Exception('Invalid authenticator');
        }

        $decrypted = sodium_crypto_secretbox_open($this->payload_secretbox, $nonce, $payload_key);

        if ($decrypted === false) {
            throw new Exception('Failed to decrypt data');
        }

        return $decrypted;
    }
}
