<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\MessagePack;

class Header
{
    const MODE_ENCRYPTION = 0;
    const MODE_ATTACHED_SIGNING = 1;
    const MODE_DETACHED_SIGNING = 2;
    const MODE_SIGNCRYPTION = 3;

    public static function decode(string $encoded, bool $unwrapped = false)
    {
        // 1-3
        $data = $unwrapped ? $encoded : MessagePack::unpack($encoded);
        $header_hash = hash('sha512', $data);
        $data = MessagePack::unpack($data);

        // 4
        if (count($data) < 2) throw new \Exception('Invalid data');

        list($format_name, $version, $mode) = $data;

        if ($format_name !== 'saltpack') throw new \Exception('Invalid data');
        if (count($version) !== 2) throw new \Exception('Invalid data');

        if ($version[0] !== 2) throw new \Exception('Unsupported version');
        if ($version[1] !== 0) throw new \Exception('Unsupported version');

        return [$header_hash, $data];
    }
}
