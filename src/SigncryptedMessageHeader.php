<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;
use MessagePack\Packer;
use MessagePack\PackOptions;
use MessagePack\Type\Bin;
use MessagePack\TypeTransformer\BinTransformer;
use BadMethodCallException;
use UnexpectedValueException;

// [
//     format name,
//     version,
//     mode,
//     ephemeral public key,
//     sender secretbox,
//     recipients list,
// ]

class SigncryptedMessageHeader extends Header
{
    const SENDER_KEY_SECRETBOX_NONCE = 'saltpack_sender_key_sbox';

    /** @var string $public_key */
    protected $public_key;

    /** @var string $sender_secretbox */
    protected $sender_secretbox;

    /** @var SigncryptedMessageRecipient[] $recipients */
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

        throw new BadMethodCallException('Unknown property "' . $key . '"');
    }

    public function __debugInfo()
    {
        return [
            'public_key' => $this->public_key,
            'sender_secretbox' => $this->sender_secretbox,
            'recipients' => $this->recipients,
        ];
    }

    public static function create(
        string $public_key, string $payload_key, ?string $sender_public_key, array $recipients
    ): SigncryptedMessageHeader
    {
        // If Alice wants to be anonymous to recipients as well, she can supply an all-zero signing public key in
        // step #3.
        if (!$sender_public_key) $sender_public_key = str_repeat("\0", 32);

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
     * @param SigncryptedMessageRecipient[] $recipients
     * @return [string, string]
     */
    public static function encodeHeader(string $public_key, string $sender, array $recipients): array
    {
        $data = [
            'saltpack',
            [2, 0],
            self::MODE_SIGNCRYPTION,
            new Bin($public_key),
            new Bin($sender),
            array_map(function (SigncryptedMessageRecipient $recipient) {
                // [
                //     recipient identifier,
                //     payload key box,
                // ]

                return [
                    new Bin($recipient->recipient_identifier),
                    new Bin($recipient->encrypted_payload_key),
                ];
            }, $recipients),
        ];

        $packer = new Packer(PackOptions::FORCE_STR, [new BinTransformer()]);
        $encoded = $packer->pack($data);

        $header_hash = hash('sha512', $encoded, true);

        return [$header_hash, MessagePack::pack($encoded, PackOptions::FORCE_BIN)];
    }

    public static function decode(string $encoded, bool $unwrapped = false): SigncryptedMessageHeader
    {
        list($header_hash, $data) = parent::decode($encoded, $unwrapped);

        if ($data[2] !== self::MODE_SIGNCRYPTION) throw new UnexpectedValueException('Invalid data');

        if (count($data) < 6) throw new UnexpectedValueException('Invalid data');

        list(,,, $public_key, $sender, $recipients) = $data;

        $index = 0;
        return new self($public_key, $sender, array_map(function (array $recipient) use (&$index) {
            return SigncryptedMessageRecipient::from($recipient[0], $recipient[1], $index++);
        }, $recipients));
    }

    /**
     * Decrypts and returns the payload key and recipient.
     */
    public function decryptPayloadKeyWithCurve25519Keypair(string $private_key): ?array
    {
        // 5. Check to see if any of the recipient's Curve25519 private keys are in the recipients' list. For each
        // private key available, and for each recipient entry in the list, compute the identifier as in step #4
        // in the previous section. If any of the recipient entries match, decrypt the payload key and proceed to
        // step #7.

        foreach ($this->recipients as $recipient) {
            list($shared_symmetric_key, $recipient_identifier) =
                SigncryptedMessageRecipient::generateRecipientIdentifierForRecipient(
                    $this->public_key, $private_key, $recipient->recipient_index
                );

            if ($recipient_identifier !== $recipient->recipient_identifier) continue;

            $payload_key = $recipient->decryptPayloadKey($shared_symmetric_key);

            if ($payload_key === null) {
                throw new Exceptions\DecryptionError('Invalid shared symmetric key');
            }

            return [$payload_key, $recipient];
        }

        return null;
    }

    public function decryptPayloadKeyWithSymmetricKey(
        string $shared_symmetric_key, ?string $recipient_identifier = null
    ): ?array
    {
        // 6. If no Curve25519 keys matched in the previous step, check whether any of the recipient's symmetric
        // keys are in the message. The identifiers in this step are up to the application, and if the space of
        // possible keys is very large, the recipient might use server assistance to look up identifiers. If any
        // of the recipient entries match, decrypt the payload key. If not, decryption fails, and the client should
        // report that the current user isn't a recipient of this message.

        foreach ($this->recipients as $recipient) {
            if ($recipient_identifier !== null && $recipient_identifier !== $recipient->recipient_identifier) continue;

            $payload_key = $recipient->decryptPayloadKey($shared_symmetric_key);
            if ($payload_key === null) continue;

            return [$payload_key, $recipient];
        }

        return null;
    }

    public function decryptSender(string $payload_key): ?string
    {
        $sender_public_key = sodium_crypto_secretbox_open(
            $this->sender_secretbox, self::SENDER_KEY_SECRETBOX_NONCE, $payload_key
        );

        if ($sender_public_key === false) {
            throw new Error('Failed to decrypt sender public key');
        }

        if ($sender_public_key === str_repeat("\0", 32)) {
            return null;
        }

        return $sender_public_key;
    }
}
