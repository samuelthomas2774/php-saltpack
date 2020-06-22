<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;
use MessagePack\PackOptions;

// [
//     format name,
//     version,
//     mode,
//     ephemeral public key,
//     sender secretbox,
//     recipients list,
// ]

class EncryptedMessageHeader extends Header
{
    const SENDER_KEY_SECRETBOX_NONCE = 'saltpack_sender_key_sbox';

    /** @var string $public_key */
    protected $public_key;

    /** @var string $sender_secretbox */
    protected $sender_secretbox;

    /** @var EncryptedMessageRecipient[] $recipients */
    protected $recipients;

    /** @var [string, string] $encoded_data */
    protected $encoded_data = null;

    public function __construct(string $public_key, string $sender_secretbox, array $recipients)
    {
        $this->public_key = $public_key;
        $this->sender_secretbox = $sender_secretbox;
        $this->recipients = $recipients;
    }

    public function __get(string $key)
    {
        if ($key === 'public_key') return $this->public_key;
        if ($key === 'sender_secretbox') return $this->sender_secretbox;
        if ($key === 'recipients') return $this->recipients;

        if (!isset($this->encoded_data) && ($key === 'encoded_data' || $key === 'encoded' || $key === 'hash')) {
            $this->encoded_data = $this->encode();
        }

        if ($key === 'encoded') return $this->encoded_data[1];
        if ($key === 'hash') return $this->encoded_data[0];

        throw new \Exception('Unknown property "' . $key . '"');
    }

    public static function create(string $public_key, string $payload_key, string $sender_public_key, array $recipients)
    {
        // 3. Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce saltpack_sender_key_sbox, to create the sender secretbox.
        $sender_secretbox = sodium_crypto_secretbox($sender_public_key, self::SENDER_KEY_SECRETBOX_NONCE, $payload_key);

        return new self($public_key, $sender_secretbox, $recipients);
    }

    public function encode()
    {
        return self::encodeHeader($this->public_key, $this->sender_secretbox, $this->recipients);
    }

    /**
     * @param int $mode
     * @param string $public_key
     * @param string $sender
     * @param EncryptedMessageRecipient[] $recipients
     * @return [string, string]
     */
    public static function encodeHeader(string $public_key, string $sender, array $recipients): array
    {
        $data = [
            'saltpack',
            [2, 0],
            self::MODE_ENCRYPTION,
            $public_key,
            $sender,
            array_map(function (EncryptedMessageRecipient $recipient) {
                // [
                //     recipient public key,
                //     payload key box,
                // ]

                return [
                    $recipient->anonymous ? null : $recipient->public_key,
                    $recipient->encrypted_payload_key,
                ];
            }, $recipients),
        ];

        $encoded = MessagePack::pack($data);

        $header_hash = hash('sha512', $encoded);

        return [$header_hash, MessagePack::pack($encoded, PackOptions::FORCE_BIN)];
    }

    public static function decode(string $encoded, bool $unwrapped = false)
    {
        list($header_hash, $data) = parent::decode($encoded, $unwrapped);

        if ($data[2] !== self::MODE_ENCRYPTION) throw new \Exception('Invalid data');

        if (count($data) < 6) throw new \Exception('Invalid data');

        list(,,, $public_key, $sender, $recipients) = $data;

        $index = 0;
        return new self($public_key, $sender, array_map(function (array $recipient) use (&$index) {
            return EncryptedMessageRecipient::from($recipient[0], $recipient[1], $index++);
        }, $recipients));
    }

    /**
     * Decrypts and returns the payload key and recipient.
     */
    public function decryptPayloadKey(string $keypair): array
    {
        $public_key = sodium_crypto_box_publickey($keypair);
        $private_key = sodium_crypto_box_secretkey($keypair);

        // 5. Precompute the ephemeral shared secret using crypto_box_beforenm with the ephemeral public key and the recipient's private key.
        // PHP's sodium extension doesn't support crypto_box_beforenm and crypto_box_open_afternm

        // 6. Try to open each of the payload key boxes in the recipients list using crypto_box_open_afternm, the precomputed secret from #5, and the nonce saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient index, where the first recipient is index 0. Successfully opening one gives the payload key.

        foreach ($this->recipients as $recipient) {
            if ($recipient->public_key) {
                // If the recipient's public key is shown in the recipients list (that is, if the recipient is not anonymous), clients may skip all the other payload key boxes in step #6.
                if ($recipient->public_key !== $public_key) continue;
            }

            $payload_key = $recipient->decryptPayloadKey($this->public_key, $private_key);
            if (!$payload_key) continue;

            $recipient->setPublicKey($public_key);

            return [$payload_key, $recipient];
        }

        throw new \Exception('$keypair is not an intended recipient');
    }

    public function decryptSender(string $payload_key): string
    {
        $sender_public_key = sodium_crypto_secretbox_open(
            $this->sender_secretbox, self::SENDER_KEY_SECRETBOX_NONCE, $payload_key
        );

        return $sender_public_key;
    }
}
