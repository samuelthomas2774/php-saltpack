<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;
use MessagePack\PackOptions;
use MessagePack\BufferUnpacker;
use React\Stream\CompositeStream;
use React\Stream\DuplexStreamInterface;

class Signing
{
    const CHUNK_LENGTH = 1024 * 1024;

    public static function sign(string $data, string $keypair, &$debug = null): string
    {
        $chunks = str_split($data, self::CHUNK_LENGTH);

        $public_key = sodium_crypto_sign_publickey($keypair);
        $private_key = sodium_crypto_sign_secretkey($keypair);

        $header = SignedMessageHeader::create($public_key, true);
        $payloads = [];

        foreach ($chunks as $i => $chunk) {
            $final = count($chunks) === ($i + 1);
            $payload = SignedMessagePayload::create($header, $private_key, $chunk, $i, $final);

            $payloads[] = $payload;
        }

        if (func_num_args() >= 3) $debug = [$header, $payloads];

        return $header->encoded . implode('', array_map(function (SignedMessagePayload $payload) {
            return $payload->encoded;
        }, $payloads));
    }

    public static function verify(string $signed, ?string &$public_key): string
    {
        $unpacker = new BufferUnpacker();
        $unpacker->reset($signed);
        $messages = $unpacker->tryUnpack();

        $header_data = array_shift($messages);
        $header = SignedMessageHeader::decode($header_data, true);

        if ($public_key === null) {
            $public_key = $header->public_key;
        } elseif ($public_key !== $header->public_key) {
            throw new Exceptions\VerifyError('Sender public key doesn\'t match');
        }

        $output = '';

        foreach ($messages as $i => $message) {
            $payload = SignedMessagePayload::decode($message, true);
            $payload->verify($header, $header->public_key, $i);

            $final = count($messages) === ($i + 1);
            if ($payload->final && !$final) {
                throw new Exceptions\InvalidFinalFlag('Found payload with invalid final flag, message extended?');
            }
            if (!$payload->final && $final) {
                throw new Exceptions\InvalidFinalFlag('Found payload with invalid final flag, message truncated?');
            }

            $output .= $payload->data;
        }

        if (empty($messages)) {
            throw new Exceptions\VerifyError('No signed payloads, message truncated?');
        }

        return $output;
    }

    public static function signStream(string $keypair): SignStream
    {
        return new SignStream($keypair);
    }

    public static function verifyStream(?string &$public_key): VerifyStream
    {
        return new VerifyStream($public_key);
    }

    public static function signAndArmor(string $data, string $keypair): string
    {
        $signed = self::sign($data, $keypair);
        return Armor::armor($signed, ['message_type' => 'SIGNED MESSAGE']);
    }

    public static function verifyArmored(string $data, ?string &$public_key): string
    {
        $dearmored = Armor::dearmor($data);
        return self::verify($dearmored, $public_key);
    }

    public static function signAndArmorStream(string $keypair): DuplexStreamInterface
    {
        $sign = new SignStream($keypair, $recipients_keys);
        $armor = new ArmorStream(['message_type' => 'SIGNED MESSAGE']);

        $sign->pipe($armor);

        return new CompositeStream($sign, $armor);
    }

    public static function verifyArmoredStream(?string &$public_key): DuplexStreamInterface
    {
        $dearmor = new DearmorStream();
        $verify = new VerifyStream($public_key);

        $dearmor->pipe($verify);

        return new CompositeStream($dearmor, $verify);
    }

    public static function signDetached(string $data, string $keypair, &$debug = null): string
    {
        $public_key = sodium_crypto_sign_publickey($keypair);
        $private_key = sodium_crypto_sign_secretkey($keypair);

        $header = SignedMessageHeader::create($public_key, false);
        $signature = MessagePack::pack($header->signDetached($data, $private_key), PackOptions::FORCE_BIN);

        if (func_num_args() >= 3) $debug = [$header, $signature];

        return $header->encoded . $signature;
    }

    public static function verifyDetached(string $signature, string $data, ?string &$public_key): void
    {
        $unpacker = new BufferUnpacker();
        $unpacker->reset($signature);

        list($header_data, $signature) = $unpacker->tryUnpack();

        $header = SignedMessageHeader::decode($header_data, true);

        $header->verifyDetached($signature, $data, $header->public_key);

        if ($public_key === null) {
            $public_key = $header->public_key;
        } elseif ($public_key !== $header->public_key) {
            throw new Exceptions\VerifyError('Sender public key doesn\'t match');
        }
    }

    public static function signDetachedAndArmor(string $data, string $keypair): string
    {
        $signed = self::signDetached($data, $keypair, $recipients_keys);
        return Armor::armor($signed, ['message_type' => 'DETACHED SIGNATURE']);
    }

    public static function verifyDetachedArmored(string $signature, string $data, ?string &$public_key): string
    {
        $dearmored = Armor::dearmor($signature);
        return self::verifyDetached($dearmored, $data, $public_key);
    }
}
