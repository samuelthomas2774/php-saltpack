<?php

declare(strict_types=1);

namespace SaltpackTests;

use PHPUnit\Framework\TestCase;
use Saltpack\Armor;

final class ArmorTest extends TestCase
{
    const INPUT_STRING = 'Two roads diverged in a yellow wood, and sorry I could not travel both' . "\n" .
        'and be one traveller, long I stood, and looked down one as far as I' . "\n" .
        'could, to where it bent in the undergrowth.';

    public function testRoundTrip(): void
    {
        $encoded = Armor::armor(self::INPUT_STRING);
        $decoded = Armor::dearmor($encoded);

        $this->assertEquals(self::INPUT_STRING, $decoded);
    }

    public function testRoundTripInRawFormat(): void
    {
        $options = [
            'raw' => true,
        ];

        $encoded = Armor::armor(self::INPUT_STRING, $options);
        $decoded = Armor::dearmor($encoded, $options);

        $this->assertEquals(self::INPUT_STRING, $decoded);
    }


    public function testBlockRoundTrip(): void
    {
        $encoded = Armor::encodeBlock(self::INPUT_STRING);
        $decoded = Armor::decodeBlock($encoded);

        $this->assertEquals(self::INPUT_STRING, $decoded);
    }

    public function testEfficientCharsSizesCanBeCalculatedForAGivenAlphabetSize(): void
    {
        $results = Armor::efficientCharsSizes(64);

        $this->assertEquals([[2, 1, 0.5], [3, 2, 0.66666666666667], [4, 3, 0.75]], $results);
    }

    public function testStreamingArmoring(): void
    {
        $options = [
            'stream_chunk_size' => $chunk_length = 3,
        ];

        $expected = str_split(Armor::armor(self::INPUT_STRING, $options), $chunk_length);
        $result = [];

        foreach (Armor::armorStream([self::INPUT_STRING], $options) as $i => $encoded_chunk) {
            $result[] = $encoded_chunk;
        }

        $this->assertEquals($expected, $result);
    }

    public function testStreamingDearmoring(): void
    {
        $options = [
            'stream_chunk_size' => $chunk_length = 3,
        ];
        $armored = Armor::armor(self::INPUT_STRING, $options);

        $expected = str_split(Armor::dearmor($armored, $options), $chunk_length);
        $result = [];

        foreach (Armor::dearmorStream([$armored], $options) as $i => $decoded_chunk) {
            $result[] = $decoded_chunk;
        }

        $this->assertEquals($expected, $result);
    }
}
