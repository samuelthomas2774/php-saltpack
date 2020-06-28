<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;

// [
//     final flag,
//     signature,
//     payload chunk,
// ]

class SignedMessagePayload
{
    const PAYLOAD_SIGNATURE_PREFIX = 'saltpack attached signature' . "\0";

    /** @var bool $final */
    protected $final;

    /** @var string $signature */
    protected $signature;

    /** @var string $data */
    protected $data;

    /** @var string $encoded_data */
    protected $encoded_data = null;

    public function __construct(bool $final, string $signature, string $data)
    {
        $this->final = $final;
        $this->signature = $signature;
        $this->data = $data;
    }

    public function __get(string $key)
    {
        if ($key === 'final') return $this->final;
        if ($key === 'signature') return $this->signature;
        if ($key === 'data') return $this->data;

        if (!isset($this->encoded_data) && $key === 'encoded') {
            $this->encoded_data = $this->encode();
        }

        if ($key === 'encoded') return $this->encoded_data;

        throw new \Exception('Unknown property "' . $key . '"');
    }

    public static function create(
        SignedMessageHeader $header, string $private_key, string $data, int $index, bool $final = false
    ): SignedMessagePayload
    {
        $sign_data = self::generateSignData($header->hash, $index, $final, $data);
        $signature = sodium_crypto_sign_detached($sign_data, $private_key);

        return new SignedMessagePayload($final, $signature, $data);
    }

    public static function generateSignData(
        string $header_hash, int $index, bool $final, string $data
    ): string
    {
        // To make each signature, the sender first takes the SHA512 hash of the concatenation of four values:

        // the header hash from above
        // the packet sequence number, as a 64-bit big-endian unsigned integer, where the first payload packet is zero
        // the final flag, a 0x00 byte for false and a 0x01 byte for true
        // the payload chunk

        return self::PAYLOAD_SIGNATURE_PREFIX .
            hash('sha512', $header_hash . pack('J', $index) . ($final ? "\x01" : "\x00") . $data, true);
    }

    public function encode()
    {
        return self::encodePayload($this->final, $this->signature, $this->data);
    }

    /**
     * @param bool $final
     * @param string $signature
     * @param string $payload_chunk
     * @return string
     */
    public static function encodePayload(bool $final, string $signature, string $payload_chunk): string
    {
        return MessagePack::pack([
            $final,
            $signature,
            $payload_chunk,
        ]);
    }

    public static function decode($encoded, $unpacked = false): SignedMessagePayload
    {
        $data = $unpacked ? $encoded : MessagePack::unpack($encoded);

        if (count($data) < 3) throw new \Exception('Invalid data');

        list($final, $signature, $payload_chunk) = $data;

        return new self($final, $signature, $payload_chunk);
    }

    public function verify(SignedMessageHeader $header, string $public_key, int $index): void
    {
        $sign_data = self::generateSignData($header->hash, $index, $this->final, $this->data);

        if (!sodium_crypto_sign_verify_detached($this->signature, $sign_data, $public_key)) {
            throw new \Exception('Invalid signature');
        }
    }
}
