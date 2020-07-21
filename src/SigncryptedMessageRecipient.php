<?php

declare(strict_types=1);

namespace Saltpack;

use BadMethodCallException;

class SigncryptedMessageRecipient
{
    const SHARED_KEY_NONCE = 'saltpack_derived_sboxkey';
    const HMAC_KEY = 'saltpack signcryption box key identifier';
    const PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 = 'saltpack_recipsb';

    /** @var string $recipient_identifier */
    protected $recipient_identifier;

    /** @var string $encrypted_payload_key */
    protected $encrypted_payload_key;

    /** @var int $index */
    protected $index;

    /** @var string $recipient_index */
    protected $recipient_index;

    public function __construct(string $recipient_identifier, string $encrypted_payload_key, int $index)
    {
        $this->recipient_identifier = $recipient_identifier;
        $this->encrypted_payload_key = $encrypted_payload_key;
        $this->index = $index;
        $this->recipient_index = self::generateRecipientIndex($index);
    }

    public function __get(string $key)
    {
        if ($key === 'recipient_identifier') return $this->recipient_identifier;
        if ($key === 'encrypted_payload_key') return $this->encrypted_payload_key;
        if ($key === 'index') return $this->index;
        if ($key === 'recipient_index') return $this->recipient_index;

        throw new BadMethodCallException('Unknown property "' . $key . '"');
    }

    public static function create(
        string $public_key, string $ephemeral_private_key, string $payload_key, int $index
    ): SigncryptedMessageRecipient
    {
        $recipient_index = self::generateRecipientIndex($index);

        list($shared_symmetric_key, $recipient_identifier) =
            self::generateRecipientIdentifierForSender($public_key, $ephemeral_private_key, $recipient_index);

        // Secretbox the payload key using this derived symmetric key, with the nonce saltpack_recipsbXXXXXXXX,
        // where XXXXXXXX is the 8-byte big-endian unsigned recipient index.
        $encrypted_payload_key = sodium_crypto_secretbox($payload_key, $recipient_index, $shared_symmetric_key);

        return new self($recipient_identifier, $encrypted_payload_key, $index);
    }

    public static function from(
        string $recipient_identifier, string $encrypted_payload_key, int $index
    ): SigncryptedMessageRecipient
    {
        return new self($recipient_identifier, $encrypted_payload_key, $index);
    }

    public static function generateRecipientIndex(int $index): string
    {
        return self::PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 . pack('J', $index);
    }

    /**
     * Decrypts the payload key.
     */
    public function decryptPayloadKey(string $shared_symmetric_key): ?string
    {
        $payload_key = sodium_crypto_secretbox_open(
            $this->encrypted_payload_key, $this->recipient_index, $shared_symmetric_key
        );

        if ($payload_key === false) {
            return null;
        }

        return $payload_key;
    }

    public static function generateRecipientIdentifierForSender(
        string $public_key, string $ephemeral_private_key, string $recipient_index
    ): array
    {
        // For Curve25519 recipient public keys, first derive a shared symmetric key by boxing 32 zero bytes with
        // the recipient public key, the ephemeral private key, and the nonce saltpack_derived_sboxkey, and taking
        // the last 32 bytes of the resulting box.
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($ephemeral_private_key, $public_key);
        $shared_symmetric_key = substr(sodium_crypto_box(str_repeat("\0", 32), self::SHARED_KEY_NONCE, $keypair), -32);

        // To compute the recipient identifier, concatenate the derived symmetric key and the
        // saltpack_recipsbXXXXXXXX nonce together, and HMAC-SHA512 them under the key saltpack signcryption box
        // key identifier. The identifier is the first 32 bytes of that HMAC.
        $recipient_identifier = substr(
            hash_hmac('sha512', $shared_symmetric_key . $recipient_index, self::HMAC_KEY, true),
            0, 32
        );

        return [$shared_symmetric_key, $recipient_identifier];
    }

    public static function generateRecipientIdentifierForRecipient(
        string $ephemeral_public_key, string $private_key, string $recipient_index
    ): array
    {
        // For Curve25519 recipient public keys, first derive a shared symmetric key by boxing 32 zero bytes with
        // the recipient public key, the ephemeral private key, and the nonce saltpack_derived_sboxkey, and taking
        // the last 32 bytes of the resulting box.
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($private_key, $ephemeral_public_key);
        $shared_symmetric_key = substr(sodium_crypto_box(str_repeat("\0", 32), self::SHARED_KEY_NONCE, $keypair), -32);

        // To compute the recipient identifier, concatenate the derived symmetric key and the
        // saltpack_recipsbXXXXXXXX nonce together, and HMAC-SHA512 them under the key saltpack signcryption box
        // key identifier. The identifier is the first 32 bytes of that HMAC.
        $recipient_identifier = substr(
            hash_hmac('sha512', $shared_symmetric_key . $recipient_index, self::HMAC_KEY, true),
            0, 32
        );

        return [$shared_symmetric_key, $recipient_identifier];
    }
}
