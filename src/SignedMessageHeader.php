<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;
use MessagePack\PackOptions;

// [
//     format name,
//     version,
//     mode,
//     sender public key,
//     nonce,
// ]

class SignedMessageHeader extends Header
{
    /** @var string|null $debug_fix_nonce */
    public static $debug_fix_nonce = null;

    /** @var string $public_key */
    protected $public_key;

    /** @var string $nonce */
    protected $nonce;

    /** @var bool $attached */
    protected $attached;

    /** @var [string, string] $encoded_data */
    protected $encoded_data = null;

    public function __construct(string $public_key, string $nonce, bool $attached = true)
    {
        $this->public_key = $public_key;
        $this->nonce = $nonce;
        $this->attached = $attached;
    }

    public function __get(string $key)
    {
        if ($key === 'public_key') return $this->public_key;
        if ($key === 'nonce') return $this->nonce;
        if ($key === 'attached') return $this->attached;

        if (!isset($this->encoded_data) && ($key === 'encoded_data' || $key === 'encoded' || $key === 'hash')) {
            $this->encoded_data = $this->encode();
        }

        if ($key === 'encoded') return $this->encoded_data[1];
        if ($key === 'hash') return $this->encoded_data[0];

        throw new \Exception('Unknown property "' . $key . '"');
    }

    public static function create(string $public_key, bool $attached = true): SignedMessageHeader
    {
        $nonce = self::$debug_fix_nonce ?? random_bytes(32);

        return new SignedMessageHeader($public_key, $nonce, $attached);
    }

    public function encode()
    {
        return self::encodeHeader($this->public_key, $this->nonce, $this->attached);
    }

    /**
     * @param string $public_key
     * @param string $nonce
     * @param bool $attached
     * @return [string, string]
     */
    public static function encodeHeader(string $public_key, string $nonce, bool $attached): array
    {
        $data = [
            'saltpack',
            [2, 0],
            $attached ? self::MODE_ATTACHED_SIGNING : self::MODE_DETACHED_SIGNING,
            $public_key,
            $nonce,
        ];

        $encoded = MessagePack::pack($data);

        $header_hash = hash('sha512', $encoded, true);

        return [$header_hash, MessagePack::pack($encoded, PackOptions::FORCE_BIN)];
    }

    public static function decode(string $encoded, bool $unwrapped = false)
    {
        list($header_hash, $data) = parent::decode($encoded, $unwrapped);

        if ($data[2] !== self::MODE_ATTACHED_SIGNING &&
            $data[2] !== self::MODE_DETACHED_SIGNING) throw new \Exception('Invalid data');

        if (count($data) < 5) throw new \Exception('Invalid data');

        list(,,, $public_key, $nonce) = $data;

        return new self($public_key, $nonce, $data[2] === self::MODE_ATTACHED_SIGNING);
    }

    public function signDetached(string $data, string $private_key): string
    {
        if ($this->attached) {
            throw new \Exception('Header $attached is true');
        }

        $hash = hash('sha512', $this->hash . $data, true);
        $sign_data = "saltpack detached signature\0" . $hash;

        return sodium_crypto_sign_detached($sign_data, $private_key);
    }

    public function verifyDetached(string $signature, string $data, string $public_key)
    {
        if ($this->attached) {
            throw new \Exception('Header $attached is true');
        }

        $hash = hash('sha512', $this->hash . $data, true);
        $sign_data = "saltpack detached signature\0" . $hash;

        if (!sodium_crypto_sign_verify_detached($signature, $sign_data, $public_key)) {
            throw new \Exception('Invalid signature');
        }
    }
}
