<?php

declare(strict_types=1);

namespace Saltpack;

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
        'stream_chunk_size' => 256,
    ];

    /** Return the index of the specified +char+ in +alphabet+, raising an appropriate error if it is not found. */
    public static function getCharIndex(string $alphabet, string $char): int
    {
        $rval = strpos($alphabet, $char);
        if ($rval === false) {
            throw new \Exception('Could not find ' . $char . ' in alphabet ' . $alphabet);
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

    /** Return the +input_bytes+ ascii-armored using the specified +options+ */
    public static function armorStream(iterable $input, array $options = []): iterable
    {
        $options = array_merge(self::DEFAULT_OPTIONS, $options);

        $stream_chunk_size = $options['stream_chunk_size'];
        if ($stream_chunk_size < 1) {
            throw new \InvalidArgumentException('$stream_chunk_size must be at least 1');
        }

        $buffer = '';

        $app = $options['app_name'] ? ' ' . $options['app_name'] : '';
        $header = 'BEGIN' . $app . ' SALTPACK ' . $options['message_type'] . '. ';
        $footer = '. END' . $app . ' SALTPACK ' . $options['message_type'] . '.';

        if (!$options['raw']) {
            $buffer .= $header;
            while (strlen($buffer) >= $stream_chunk_size) {
                yield substr($buffer, 0, $stream_chunk_size);
                $buffer = substr($buffer, $stream_chunk_size);
            }
        }

        $in_buffer = '';
        $output = '';
        $words = 0;

        foreach ($input as $i => $chunk) {
            if (self::$debug) echo 'Processing chunk #' . $i . ': ' . $chunk . PHP_EOL;

            $in_buffer .= $chunk;

            while (strlen($in_buffer) > $options['block_size']) {
                $block = substr($in_buffer, 0, $options['block_size']);
                $in_buffer = substr($in_buffer, $options['block_size']);

                $output .= self::encodeBlock($block, $options['alphabet'], $options['shift']);
            }

            if ($options['raw']) {
                while (strlen($output) > 43) {
                    $buffer .= substr($output, 0, 43) . ' ';
                    $output = substr($output, 43);
                }
            } else {
                while (strlen($output) > 15) {
                    $buffer .= $word = substr($output, 0, 15);
                    $output = substr($output, 15);
                    $words++;

                    if ($words >= 200) {
                        $buffer .= "\n";
                        $words = 0;
                    } else {
                        $buffer .= ' ';
                    }
                }
            }

            while (strlen($buffer) >= $stream_chunk_size) {
                yield substr($buffer, 0, $stream_chunk_size);
                $buffer = substr($buffer, $stream_chunk_size);
            }
        }

        if (strlen($in_buffer) > 0) {
            $output .= self::encodeBlock($in_buffer, $options['alphabet'], $options['shift']);
            $in_buffer = '';
        }

        if ($options['raw']) {
            while (strlen($output) > 43) {
                $buffer .= substr($output, 0, 43) . ' ';
                $output = substr($output, 43);
            }
        } else {
            while (strlen($output) > 15) {
                $buffer .= $word = substr($output, 0, 15);
                $output = substr($output, 15);
                $words++;

                if ($words >= 200) {
                    $buffer .= "\n";
                    $words = 0;
                } else {
                    $buffer .= ' ';
                }
            }
        }

        $buffer .= $output;

        if (!$options['raw']) {
            $buffer .= $footer;
        }

        while (strlen($buffer) >= $stream_chunk_size) {
            yield substr($buffer, 0, $stream_chunk_size);
            $buffer = substr($buffer, $stream_chunk_size);
        }

        if (strlen($buffer) > 0) {
            yield $buffer;
        }
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
                throw new \Exception('Invalid header');
            }

            $header_info = [
                'message_type' => $match[3],
                'app_name' => $match[2],
            ];

            if (!preg_match(self::FOOTER_REGEX, $footer, $match)) {
                throw new \Exception('Invalid footer');
            }
            if ($header_info['message_type'] !== $match[3] ||
                $header_info['app_name'] !== $match[2]
            ) {
                throw new \Exception('Footer doesn\'t match header');
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

    /** Decode the ascii-armored data from the specified +input_chars+ using the given +options+. */
    public static function dearmorStream(iterable $input, array $options = [], ?array $header_info = null): iterable
    {
        $options = array_merge(self::DEFAULT_OPTIONS, $options);

        $stream_chunk_size = $options['stream_chunk_size'];
        if ($stream_chunk_size < 1) {
            throw new \InvalidArgumentException('$stream_chunk_size must be at least 1');
        }

        $output = '';

        $buffer = '';
        $header = null;
        $header_match = null;
        $footer = null;

        foreach ($input as $i => $chunk) {
            if (self::$debug) echo 'Processing chunk #' . $i . ': ' . $chunk . PHP_EOL;

            if (!$options['raw'] && $header === null) {
                $buffer .= $chunk;

                $index = strpos($buffer, '.');
                if ($index === false) continue;

                $header = substr($buffer, 0, $index);
                $chunk = substr($buffer, $index + 1);
                $buffer = '';

                if (!preg_match(self::HEADER_REGEX, $header, $header_match)) {
                    throw new \Exception('Invalid header');
                }
    
                $header_info = [
                    'message_type' => $header_match[3],
                    'app_name' => $header_match[2],
                ];

                if (self::$debug) echo 'Read header: ' . $header . PHP_EOL;
            }

            if (!$options['raw'] && $footer !== null) {
                $footer .= $chunk;

                $remaining_index = strpos($footer, '.');
                if ($remaining_index !== false) {
                    $footer = substr($footer, 0, $remaining_index);
                    break;
                }
            }

            if (!$options['raw'] && $footer === null) {
                $index = strpos($chunk, '.');
                if ($index !== false) {
                    $footer = substr($chunk, $index + 1);
                    $chunk = substr($chunk, 0, $index);
                    $buffer .= str_replace(['>', "\n", "\r", "\t", ' '], '', $chunk);

                    $remaining_index = strpos($footer, '.');
                    if ($remaining_index !== false) {
                        $footer = substr($footer, 0, $remaining_index);
                        break;
                    }

                    continue;
                }
            }

            if ($options['raw'] || $footer === null) {
                $buffer .= str_replace(['>', "\n", "\r", "\t", ' '], '', $chunk);

                while (strlen($buffer) > $options['char_block_size']) {
                    $block = substr($buffer, 0, $options['char_block_size']);
                    $buffer = substr($buffer, $options['char_block_size']);

                    $output .= self::decodeBlock($block, $options['alphabet'], $options['shift']);
                }
            }

            while (strlen($output) >= $stream_chunk_size) {
                yield substr($output, 0, $stream_chunk_size);
                $output = substr($output, $stream_chunk_size);
            }
        }

        while (strlen($buffer) > $options['char_block_size']) {
            $block = substr($buffer, 0, $options['char_block_size']);
            $buffer = substr($buffer, $options['char_block_size']);

            $output .= self::decodeBlock($block, $options['alphabet'], $options['shift']);
        }

        if (strlen($buffer) > 0) {
            $output .= self::decodeBlock($buffer, $options['alphabet'], $options['shift']);
            $buffer = '';
        }

        if (!$options['raw'] && $footer === null) {
            throw new \Exception('Input stream doesn\'t contain a valid header and footer');
        }

        if (!$options['raw']) {
            if (!preg_match(self::FOOTER_REGEX, $footer, $match)) {
                throw new \Exception('Invalid footer');
            }
            if ($header_match[3] !== $match[3] ||
                $header_match[2] !== $match[2]
            ) {
                throw new \Exception('Footer doesn\'t match header');
            }

            if (self::$debug) echo 'Read footer: ' . $footer . PHP_EOL;
        }

        while (strlen($output) >= $stream_chunk_size) {
            yield substr($output, 0, $stream_chunk_size);
            $output = substr($output, $stream_chunk_size);
        }

        if (strlen($output) > 0) {
            yield $output;
        }
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
            throw new \InvalidArgumentException('Illegal block size ' . strlen($chars_block) . ', expected ' .
                $expected_block_size);
        }

        $extra = self::extraBits(strlen($alphabet), strlen($chars_block), $bytes_size);

        $bytes_int = gmp_init(self::getCharIndex($alphabet, $chars_block[0]));
        for ($i = 1; $i < strlen($chars_block); $i++) {
            $bytes_int = gmp_mul($bytes_int, (string) strlen($alphabet));
            $bytes_int = gmp_add($bytes_int, self::getCharIndex($alphabet, $chars_block[$i]));
        }

        if ($shift) {
            // TODO
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
