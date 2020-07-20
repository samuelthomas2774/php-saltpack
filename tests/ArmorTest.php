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

    const ARMORED = 'BEGIN SALTPACK MESSAGE. K1pqnxb2DkrYwTF eoRpTHfQUiQ8Vhv QcqV2Ijl5OgvHQQ KXoeeJBRilQ1udq ' .
        'YjHoEWwyIgddRVZ SEswTz7nRxdPdgd RVjkX80hz6eArwG S2IaonQ5sEZH3Ia 5qxopd0rWOSAd4W 1MLaAPG3aIif4yU ' .
        'ymurJJlPkXjIGfc L3GAOA5RIbPD2mW YBGP8Ky5cPTzjIv ZERus8MRXpGXzas nYYCr4KgnLRUZEp 3juuuL5RLE5A4qX ' .
        '6jbmY. END SALTPACK MESSAGE.';

    const BLOCK = '2ytpAzEXyKTYKdqtKuPHhGNeLdnK5QUeASwFqeXVWkPZUADyvXCVJfrkMjWEztpm' .
        'SyeH2zB3i6pZhR00wiGVBAvnVRRqrqjLhhRJkRKc3qS9uVeVKxOiYtV3LIx0sD4L' .
        'uuwO6Qocfg57zXTelzCbdFgwBQZCqdTxAG0Oc9RygG8SI9YKvlTeAzPaSj76T2vG' .
        'B0Gyl6ELQQIbcBmMBriz2cwFTfY31Y8lzI6EhKIYWYik0WUa823uY';

    const ENCRYPTED_HEX = 'c4b896a873616c747061636b92020000c4205bf55c73b82ebe22be80f3430667' .
        'af570fae2556a6415e6b30d4065300aa947dc43094992d83ef6d054728b19b77' .
        'f91640d4b6fc921440138f7d571fb1796e44fd8f780f153e4507d3ed7f500b48' .
        'b6e752df9192c42060346e7c911a5f6ba154129174cafe75b294ac3bbd554963' .
        '2f48cec6266f8410c4302159708fbf1824787d5872df43734dd567672f70eab9' .
        '663ef62165ca5653e24de796b9f2951c87971d4c23a649984dc693c391c42020' .
        '755fe80a6ccb4486993bf69cc8f5050f26ec8850fb776fca4ce22ef665f056c4' .
        'c64d6cbc4477493be11cb91110ead53afd99f227025700b3d93f6fea2f2bcd90' .
        '5c170488bbb342b33fad6c3b8037e787d7f310a6a4240bfaca5ba3867e42a685' .
        'a0de9eb12c5c7d51b13749c5e7607e5ab187b584e0bc35ac6a9b17e3a1bd717f' .
        'b4f7c6ffad48afad5fa1d44faef31554c2fce0f2dbc6a215761eb10e664bd353' .
        '156eb13da776b51c049d1ead133542cbdf8b5ffb124bbe82184bce9c0d9da611' .
        '0e47f69a40d3c365f9c2e3fc4178ac36deadd61bbc0817a8cf7cf5bf944c228b' .
        'e675888b05c84e';
    const ENCRYPTED_ARMORED = 'BEGIN SALTPACK MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ ' .
        'rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P 34lAW3U7RD7FIch XNTBGUhFUP7zlJO 72a09uarIhN4God ' .
        'BYvOpzyUOcjDNz2 a8Tu9CgP2XrrVb5 sGTJN7TBDBBrSwc Q6L50iicGl3ayIM Y02zOx5wnJk4oOC fbt3xOFEKC2HCM0 ' .
        'hDNu9HFeexApAaz mY6uuYwjeCx2moo YroRpeao26spsF9 iSD6UmL7gPjA3YU lFZvtJYx6t3eKlN sl1SmPnLCnhyV9L ' .
        '10hYj7F8YELWJKA BKpZBWnw48xQGWL pun4FEAQONeTnpO 0idRsM41lLrgDeS aHRkSXH702Wjc97 bLKV43Et1MFYwFm ' .
        'P6nFMM0hj0hupfj umu3at5TV1gubnJ snULAcpBmzBTVxK DkjxM3n3mWZdDlK UB9TCTeV556HgaO 15nEqRYJGO2b5RL ' .
        'gu9931xVkZ0wT20 kCLWHR3NxfRTp6R 9rKEP8b2F178xSC lwenoSpkzd5mA2r 2JRr4n65rNdbiw. END SALTPACK MESSAGE.';
    const ENCRYPTED_BLOCK = '36lQllTIba4NtvPlWu5xM6jpvab7TBfZRFBNv5FxldjX9bV69ziu7zYLVqBmRKXg' .
        'KN5xi5kRCOgY5iwCRJtUPGidCzZIb94gvwEV9RXMHHc1JGcwyqMYkJRcnKglUfex' .
        'L9VC4LhMmeRunKcpCkXXoLwcKMy4OvWSZ15xGkrZ8TNLMCBph31OsiFwB9Na5kwB' .
        '8uaH0p2Dd4h6EgoJZX5syw7d3n3qghBWfgna2AUeILBxMXj35KrDV1DOd5WwfXeH' .
        '1gCGP9fb2eFySjp0hr0bOlk6ya6F4GItnH3NPmV01PioOCn0C6a3AYARrQnKgjY3' .
        '9oJzaC9dCS1TeRlFOs95W4MAbmDkOeiOy72BeCdrKVfmXEJMfuRAkRO2fha9hoWA' .
        '4AhkRyKwdkWkJWsRsYrGz3NXfxdii7Ym8kooOuMN3qnlMz5Nq5eIpzitNuHIIIj6' .
        'cnJdyhGkrdUJM6mpJU8KugT2Kyn738zhWLc1wVZ3RFCNOItOxmRsFbL4LlOHkmYx' .
        'azgAmok5ZXHhojGVt3XsND42ZPTYgAaXOQBHB6BcqG3E8thWrqmms0RhO';

    public function testArmor(): void
    {
        $encoded = Armor::armor(self::INPUT_STRING);

        $this->assertEquals(self::ARMORED, $encoded);
    }

    public function testDearmor(): void
    {
        $decoded = Armor::dearmor(self::ARMORED);

        $this->assertEquals(self::INPUT_STRING, $decoded);
    }

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

    public function testArmorBinary(): void
    {
        $encoded = Armor::armor(hex2bin(self::ENCRYPTED_HEX));

        $this->assertEquals(self::ENCRYPTED_ARMORED, $encoded);
    }

    public function testDearmorBinary(): void
    {
        $decoded = Armor::dearmor(self::ENCRYPTED_ARMORED);

        $this->assertEquals(self::ENCRYPTED_HEX, bin2hex($decoded));
        $this->assertEquals(hex2bin(self::ENCRYPTED_HEX), $decoded);
    }

    public function testEncodeBlock(): void
    {
        $encoded = Armor::encodeBlock(self::INPUT_STRING);

        $this->assertEquals(self::BLOCK, $encoded);
    }

    public function testDecodeBlock(): void
    {
        $decoded = Armor::decodeBlock(self::BLOCK);

        $this->assertEquals(self::INPUT_STRING, $decoded);
    }

    public function testEncodeBinaryBlock(): void
    {
        $encoded = Armor::encodeBlock(hex2bin(self::ENCRYPTED_HEX));

        $this->assertEquals(self::ENCRYPTED_BLOCK, $encoded);
    }

    public function testDecodeBinaryBlock(): void
    {
        $decoded = Armor::decodeBlock(self::ENCRYPTED_BLOCK);

        $this->assertEquals(self::ENCRYPTED_HEX, bin2hex($decoded));
        $this->assertEquals(hex2bin(self::ENCRYPTED_HEX), $decoded);
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
