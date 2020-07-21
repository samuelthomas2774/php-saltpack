<?php

declare(strict_types=1);

namespace Saltpack;

use InvalidArgumentException;

class Armor
{
    /** @var bool $debug */
    public static $debug = false;

    /** The Base62 alphabet */
    const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /** The Base64 alphabet */
    const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    /** The Base85 alphabet */
    const BASE85_ALPHABET = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' .
        '[\\]^_`abcdefghijklmnopqrstu';

    // Also accept message type "MESSAGE"
    // (should really be "ENCRYPTED MESSAGE", "SIGNED MESSAGE" or "DETACHED SIGNATURE")
    const HEADER_REGEX = '/^[>\n\r\t ]*BEGIN[>\n\r\t ]+(([a-zA-Z0-9]+)[>\n\r\t ]+)?SALTPACK[>\n\r\t ]+(MESSAGE|ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$/';
    const FOOTER_REGEX = '/^[>\n\r\t ]*END[>\n\r\t ]+(([a-zA-Z0-9]+)[>\n\r\t ]+)?SALTPACK[>\n\r\t ]+(MESSAGE|ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$/';

    /** The default options used by the ::armor/::dearmor methods. */
    const DEFAULT_OPTIONS = [
        'alphabet' => self::BASE62_ALPHABET,
        'block_size' => 32,
        'char_block_size' => 43,
        'raw' => false,
        'shift' => false,
        'message_type' => 'MESSAGE',
        'app_name' => null, // Application name (e.g. "KEYBASE")
    ];

    /** Return the index of the specified +char+ in +alphabet+, raising an appropriate error if it is not found. */
    public static function getCharIndex(string $alphabet, string $char): int
    {
        $rval = strpos($alphabet, $char);
        if ($rval === false) {
            throw new InvalidArgumentException('Could not find ' . $char . ' in alphabet ' . $alphabet);
        }
        return $rval;
    }

    /** Return the minimum number of characters needed to encode +bytes_size+ bytes using the given +alphabet+. */
    public static function characterBlockSize(int $alphabet_size, int $bytes_size): int
    {
        return (int) ceil(8 * $bytes_size / log($alphabet_size, 2));
    }

	/** Return the maximum number of bytes needed to encode +chars_size+ characters using the given +alphabet+. */
    public static function maxBytesSize(int $alphabet_size, int $chars_size): int
    {
	    return (int) floor(log($alphabet_size, 2) / 8 * $chars_size);
    }

    /**
     * Return the number of bits left over after using an alphabet of the specified +alphabet_size+ to encode a
     * payload of +bytes_size+ with +chars_size+ characters.
     */
    public static function extraBits(int $alphabet_size, int $chars_size, int $bytes_size): int
    {
	    $total_bits = (int) floor(log($alphabet_size, 2) * $chars_size);
	    return $total_bits - 8 * $bytes_size;
	}

    /** Return the +input_bytes+ ascii-armored using the specified +options+ */
    public static function armor(string $input, array $options = []): string
    {
        $options = array_merge(self::DEFAULT_OPTIONS, $options);
        $chunks = str_split($input, $options['block_size']);

        $output = '';
        foreach ($chunks as $chunk) {
            $output .= self::encodeBlock($chunk, $options['alphabet'], $options['shift']);
        }

        if ($options['raw']) {
            $out_chunks = str_split($output, 43);
            return implode(' ', $out_chunks);
        }

        $word_chunks = str_split($output, 15);
        $sentences = array_chunk($word_chunks, 200);

        $joined = implode("\n", array_map(function ($words) {
            return implode(' ', $words);
        }, $sentences));

        $app = $options['app_name'] ? ' ' . $options['app_name'] : '';
        $header = 'BEGIN' . $app . ' SALTPACK ' . $options['message_type'] . '. ';
        $footer = '. END' . $app . ' SALTPACK ' . $options['message_type'] . '.';

        return $header . $joined . $footer;
    }

    /** Decode the ascii-armored data from the specified +input_chars+ using the given +options+. */
    public static function dearmor(
        string $input, array $options = [], ?string &$remaining = null, ?array &$header_info = null
    ): string
    {
        $options = array_merge(self::DEFAULT_OPTIONS, $options);

        if (!$options['raw']) {
            list($header, $input, $footer, $remaining) = explode('.', $input, 4);

            if (!preg_match(self::HEADER_REGEX, $header, $match)) {
                throw new Exceptions\InvalidArmorFraming('Invalid header');
            }

            $header_info = [
                'message_type' => $match[3],
                'app_name' => $match[2],
            ];

            if (!preg_match(self::FOOTER_REGEX, $footer, $match)) {
                throw new Exceptions\InvalidArmorFraming('Invalid footer');
            }
            if ($header_info['message_type'] !== $match[3] ||
                $header_info['app_name'] !== $match[2]
            ) {
                throw new Exceptions\InvalidArmorFraming('Footer doesn\'t match header');
            }
        }

        $input = str_replace(['>', "\n", "\r", "\t", ' '], '', $input);
        $chunks = str_split($input, $options['char_block_size']);

        $output = '';
        foreach ($chunks as $chunk) {
            $output .= self::decodeBlock($chunk, $options['alphabet'], $options['shift']);
        }

        return $output;
    }

    /** Encode a single block of ascii-armored output from +bytes_block+ using the specified +alphabet+ and +shift+. */
    public static function encodeBlock(
        string $bytes_block, string $alphabet = self::BASE62_ALPHABET, bool $shift = false
    ): string
    {
        $block_size = self::characterBlockSize(strlen($alphabet), strlen($bytes_block));
        $extra = self::extraBits(strlen($alphabet), $block_size, strlen($bytes_block));

        // Convert the bytes into an integer, big-endian
        $bytes_int = gmp_import($bytes_block, 1, GMP_BIG_ENDIAN);

        if ($shift) {
            $n = 1;
            for ($i = 0; $i > $extra; $i++) $n = $n * 2;
            $bytes_int = gmp_mul($bytes_int, (string) $n);
        }

        $places = [];
        for ($i = 0; $i < $block_size; $i++) {
            $rem = gmp_div_r($bytes_int, (string) strlen($alphabet));
            array_unshift($places, gmp_intval($rem));
            $bytes_int = gmp_div_q($bytes_int, (string) strlen($alphabet));
        }

        return implode('', array_map(function ($i) use ($alphabet) {
            return $alphabet[$i];
        }, $places));
    }

    /** Decode the specified ascii-armored +chars_block+ using the specified +alphabet+ and +shift+. */
    public static function decodeBlock(
        string $chars_block, string $alphabet = self::BASE62_ALPHABET, bool $shift = false
    ): string
    {
        $bytes_size = self::maxBytesSize(strlen($alphabet), strlen($chars_block));
        $expected_block_size = self::characterBlockSize(strlen($alphabet), $bytes_size);

        if (strlen($chars_block) !== $expected_block_size) {
            throw new InvalidArgumentException('Illegal block size ' . strlen($chars_block) . ', expected ' .
                $expected_block_size);
        }

        $extra = self::extraBits(strlen($alphabet), strlen($chars_block), $bytes_size);

        $bytes_int = gmp_init(self::getCharIndex($alphabet, $chars_block[0]));
        for ($i = 1; $i < strlen($chars_block); $i++) {
            $bytes_int = gmp_mul($bytes_int, (string) strlen($alphabet));
            $bytes_int = gmp_add($bytes_int, self::getCharIndex($alphabet, $chars_block[$i]));
        }

        if ($shift) {
            $n = 1;
            for ($i = 0; $i > $extra; $i++) $n = $n * 2;
            $bytes_int = gmp_div_q($bytes_int, (string) $n);
        }

        return gmp_export($bytes_int, 1, GMP_BIG_ENDIAN);
    }

	/**
     * Return a table of the most efficient number of characters to use between 1 and +chars_size_upper_bound+ using
     * an alphabet of +alphabet_size+. Each row of the resulting Array will be a tuple of:
     * [ character_size, byte_size, efficiency ]
     */
    public static function efficientCharsSizes(int $alphabet_size, int $chars_size_upper_bound = 50): array
    {
        $out = [];
        $max_efficiency = 0;

        for ($chars_size = 1; $chars_size < $chars_size_upper_bound; $chars_size++) {
            $bytes_size = self::maxBytesSize($alphabet_size, $chars_size);
            $efficiency = $bytes_size / $chars_size;

            if ($efficiency > $max_efficiency) {
                array_push($out, [$chars_size, $bytes_size, $efficiency]);
                $max_efficiency = $efficiency;
            }
        }

        return $out;
    }
}
