<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\BufferUnpacker;
use React\Stream\CompositeStream;
use React\Stream\DuplexStreamInterface;

class Signcryption
{
    const CHUNK_LENGTH = 1024 * 1024;

    public static $debug_fix_key = null;
    public static $debug_fix_keypair = null;

    /**
     * @param string $data
     * @param string|null $keypair
     * @param string[] $recipients_keys
     */
    public static function encrypt(string $data, ?string $keypair, array $recipients_keys): string
    {
        $chunks = str_split($data, self::CHUNK_LENGTH);

        // 1. Generate a random 32-byte payload key.
        $payload_key = self::$debug_fix_key ?? random_bytes(32);

        // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
        $ephemeral_keypair = self::$debug_fix_keypair ?? sodium_crypto_box_keypair();
        $public_key = sodium_crypto_box_publickey($ephemeral_keypair);
        $private_key = sodium_crypto_box_secretkey($ephemeral_keypair);

        $sender_public_key = $keypair ? sodium_crypto_sign_publickey($keypair) : null;
        $sender_private_key = $keypair ? sodium_crypto_sign_secretkey($keypair) : null;

        $index = 0;
        $recipients = array_map(function (string $recipient_key) use (&$index, $private_key, $payload_key) {
            return SigncryptedMessageRecipient::create($recipient_key, $private_key, $payload_key, $index++);
        }, $recipients_keys);

        $header = SigncryptedMessageHeader::create($public_key, $payload_key, $sender_public_key, $recipients);

        $payloads = [];

        foreach ($chunks as $i => $chunk) {
            $final = count($chunks) === ($i + 1);
            $payload = SigncryptedMessagePayload::create(
                $header, $payload_key, $sender_private_key, $chunk, $i, $final
            );

            $payloads[] = $payload;
        }

        return $header->encoded . implode('', array_map(function (SigncryptedMessagePayload $payload) {
            return $payload->encoded;
        }, $payloads));
    }

    public static function decrypt(string $encrypted, string $keypair, string &$sender = null): string
    {
        $unpacker = new BufferUnpacker();
        $unpacker->reset($encrypted);
        $messages = $unpacker->tryUnpack();

        $header_data = array_shift($messages);
        $header = SigncryptedMessageHeader::decode($header_data, true);

        $private_key = sodium_crypto_box_secretkey($keypair);

        // TODO: handle other recipient types
        list($payload_key, $recipient) = $header->decryptPayloadKeyWithCurve25519Keypair($private_key);
        if ($payload_key === null) throw new Exceptions\DecryptionError('$keypair is not an intended recipient');
        $sender_public_key = $header->decryptSender($payload_key);

        if (isset($sender) && $sender !== $sender_public_key) {
            throw new Exception\VerifyError('Sender public key doesn\'t match');
        } else if ($header->public_key !== $sender_public_key) {
            $sender = $sender_public_key;
        }

        $output = '';

        foreach ($messages as $i => $message) {
            $payload = SigncryptedMessagePayload::decode($message, true);

            $final = count($messages) === ($i + 1);
            if ($payload->final && !$final) {
                throw new Exceptions\InvalidFinalFlag('Found payload with invalid final flag, message extended?');
            }
            if (!$payload->final && $final) {
                throw new Exceptions\InvalidFinalFlag('Found payload with invalid final flag, message truncated?');
            }

            $output .= $payload->decrypt($header, $sender_public_key, $payload_key, $i);
        }

        return $output;
    }

    public static function encryptStream(?string $keypair, array $recipients_keys): SigncryptStream
    {
        return new SigncryptStream($keypair, $recipients_keys);
    }

    public static function decryptStream(?string $keypair): DesigncryptStream
    {
        return new DesigncryptStream($keypair);
    }

    public static function encryptAndArmor(string $data, ?string $keypair, array $recipients_keys): string
    {
        $encrypted = self::encrypt($data, $keypair, $recipients_keys);
        return Armor::armor($encrypted, ['message_type' => 'ENCRYPTED MESSAGE']);
    }

    public static function dearmorAndDecrypt(string $data, string $keypair): string
    {
        $dearmored = Armor::dearmor($data);
        return self::decrypt($dearmored, $keypair);
    }

    public static function encryptAndArmorStream(?string $keypair, array $recipients_keys): DuplexStreamInterface
    {
        $encrypt = new SigncryptStream($keypair, $recipients_keys);
        $armor = new ArmorStream(['message_type' => 'ENCRYPTED MESSAGE']);

        $encrypt->pipe($armor);

        return new CompositeStream($encrypt, $armor);
    }

    public static function dearmorAndDecryptStream(?string $keypair): DuplexStreamInterface
    {
        $dearmor = new DearmorStream();
        $decrypt = new DesigncryptStream($keypair);

        $dearmor->pipe($decrypt);

        return new CompositeStream($dearmor, $decrypt);
    }
}
