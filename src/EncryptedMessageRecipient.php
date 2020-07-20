<?php

declare(strict_types=1);

namespace Saltpack;

use BadMethodCallException;

class EncryptedMessageRecipient
{
    const PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 = 'saltpack_recipsb';

    /** @var string|null $public_key */
    protected $public_key;

    /** @var string $encrypted_payload_key */
    protected $encrypted_payload_key;

    /** @var int $index */
    protected $index;

    /** @var string $recipient_index */
    protected $recipient_index;

    /** @var bool $anonymous */
    protected $anonymous;

    /** @var string|null $mac_key */
    protected $mac_key = null;

    public function __construct(?string $public_key, string $encrypted_payload_key, int $index, bool $anonymous = false)
    {
        $this->public_key = $public_key;
        $this->encrypted_payload_key = $encrypted_payload_key;
        $this->index = $index;
        $this->recipient_index = self::generateRecipientIndex($index);
        $this->anonymous = $anonymous;
    }

    public function __get(string $key)
    {
        if ($key === 'public_key') return $this->public_key;
        if ($key === 'encrypted_payload_key') return $this->encrypted_payload_key;
        if ($key === 'index') return $this->index;
        if ($key === 'recipient_index') return $this->recipient_index;
        if ($key === 'anonymous') return $this->anonymous;
        if ($key === 'mac_key') return $this->mac_key;

        throw new BadMethodCallException('Unknown property "' . $key . '"');
    }

    /** @private */
    public function setPublicKey(string $public_key)
    {
        $this->public_key = $public_key;
    }

    public static function create(
        string $public_key, string $ephemeral_private_key, string $payload_key, int $index, bool $anonymous = false
    ): EncryptedMessageRecipient
    {
        $recipient_index = self::generateRecipientIndex($index);

        // 4. For each recipient, encrypt the payload key using crypto_box with the recipient's public key, the ephemeral private key, and the nonce saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient index, where the first recipient is index zero. Pair these with the recipients' public keys, or null for anonymous recipients, and collect the pairs into the recipients list.
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($ephemeral_private_key, $public_key);
        $encrypted_payload_key = sodium_crypto_box($payload_key, $recipient_index, $keypair);

        return new self($public_key, $encrypted_payload_key, $index, $anonymous);
    }

    public static function from(
        ?string $public_key, string $encrypted_payload_key, int $index
    ): EncryptedMessageRecipient
    {
        return new self($public_key, $encrypted_payload_key, $index, $public_key === null);
    }

    public static function generateRecipientIndex(int $index): string
    {
        return self::PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 . pack('J', $index);
    }

    /**
     * Decrypts the payload key, returns null if wrong recipient.
     */
    public function decryptPayloadKey(
        string $ephemeral_public_key, string $recipient_private_key, ?string $secret = null
    ): ?string
    {
        // PHP's sodium extension doesn't support crypto_box_beforenm and crypto_box_open_afternm
        if ($secret) throw new BadMethodCallException('Not supported');

        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $recipient_private_key, $ephemeral_public_key
        );

        $payload_key = sodium_crypto_box_open($this->encrypted_payload_key, $this->recipient_index, $keypair);
        if (!$payload_key) return null;

        return $payload_key;
    }

    public function generateMacKeyForSender(
        string $header_hash, string $ephemeral_private_key, string $sender_private_key, ?string $public_key = null
    ): string
    {
        if (!$public_key && $this->public_key) $public_key = $this->public_key;
        if (!$public_key) throw new BadMethodCallException('Generating MAC key requires the recipient\'s public key');

        // 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the recipient index from
        // step 4 above. This is the basis of each recipient's MAC nonce.
        $nonce = substr($header_hash, 0, 16) . pack('J', $this->index);

        // 10. Clear the least significant bit of byte 15. That is: nonce[15] &= 0xfe.
        $nonce[15] = chr(ord($nonce[15]) & 0xfe);

        // 11. Encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term
        // private key, and the nonce from the previous step.
        $box_1_key = sodium_crypto_box_keypair_from_secretkey_and_publickey($sender_private_key, $public_key);
        $box_1 = sodium_crypto_box(str_repeat("\0", 32), $nonce, $box_1_key);

        // 12. Modify the nonce from step 10 by setting the least significant bit of byte
        // 12.1. That is: nonce[15] |= 0x01.
        $nonce[15] = chr(ord($nonce[15]) | 0x01);

        // 13. Encrypt 32 zero bytes again, as in step 11, but using the ephemeral private key rather than the
        // sender's long term private key.
        $box_2_key = sodium_crypto_box_keypair_from_secretkey_and_publickey($ephemeral_private_key, $public_key);
        $box_2 = sodium_crypto_box(str_repeat("\0", 32), $nonce, $box_2_key);

        // 14. Concatenate the last 32 bytes each box from steps 11 and 13. Take the SHA512 hash of that
        // concatenation. The recipient's MAC Key is the first 32 bytes of that hash.
        return $this->mac_key = substr(hash('sha512', substr($box_1, -32) . substr($box_2, -32), true), 0, 32);
    }

    public function generateMacKeyForRecipient(
        string $header_hash, string $ephemeral_public_key, string $sender_public_key, string $private_key
    ): string
    {
        // 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the recipient index from
        // step 4 above. This is the basis of each recipient's MAC nonce.
        $nonce = substr($header_hash, 0, 16) . pack('J', $this->index);

        // 10. Clear the least significant bit of byte 15. That is: nonce[15] &= 0xfe.
        $nonce[15] = chr(ord($nonce[15]) & 0xfe);

        // 11. Encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term
        // private key, and the nonce from the previous step.
        $box_1_key = sodium_crypto_box_keypair_from_secretkey_and_publickey($private_key, $sender_public_key);
        $box_1 = sodium_crypto_box(str_repeat("\0", 32), $nonce, $box_1_key);

        // 12. Modify the nonce from step 10 by setting the least significant bit of byte
        // 12.1. That is: nonce[15] |= 0x01.
        $nonce[15] = chr(ord($nonce[15]) | 0x01);

        // 13. Encrypt 32 zero bytes again, as in step 11, but using the ephemeral private key rather than the
        // sender's long term private key.
        $box_2_key = sodium_crypto_box_keypair_from_secretkey_and_publickey($private_key, $ephemeral_public_key);
        $box_2 = sodium_crypto_box(str_repeat("\0", 32), $nonce, $box_2_key);

        // 14. Concatenate the last 32 bytes each box from steps 11 and 13. Take the SHA512 hash of that
        // concatenation. The recipient's MAC Key is the first 32 bytes of that hash.
        return $this->mac_key = substr(hash('sha512', substr($box_1, -32) . substr($box_2, -32), true), 0, 32);
    }
}
