<?php

declare(strict_types=1);

namespace SaltpackTests;

use PHPUnit\Framework\TestCase;
use Saltpack\Armor;
use Saltpack\Encryption;
use Saltpack\EncryptedMessageHeader;

final class EncryptionTest extends TestCase
{
    const INPUT_STRING = 'Two roads diverged in a yellow wood, and sorry I could not travel both' . "\n" .
        'and be one traveller, long I stood, and looked down one as far as I' . "\n" .
        'could, to where it bent in the undergrowth.';

    // Encrypted with a hardcoded keypair
    const ENCRYPTED_HEX = 'c4b896a873616c747061636b92020000c4205bf55c73b82ebe22be80f3430667' .
        'af570fae2556a6415e6b30d4065300aa947dc43094992d83ef6d054728b19b77' .
        'f91640d4b6fc921440138f7d571fb1796e44fd8f780f153e4507d3ed7f500b48' .
        'b6e752df9192c42060346e7c911a5f6ba154129174cafe75b294ac3bbd554963' .
        '2f48cec6266f8410c4302159708fbf1824787d5872df43734dd567672f70eab9' .
        '663ef62165ca5653e24de796b9f2951c87971d4c23a649984dc693c391c42083' .
        'fa7e17a279e059c8c0f9d9fe436840cc403fd327d10c922218474f21c08f0bc4' .
        'c64d6cbc4477493be11cb91110ead53afd99f227025700b3d93f6fea2f2bcd90' .
        '5c170488bbb342b33fad6c3b8037e787d7f310a6a4240bfaca5ba3867e42a685' .
        'a0de9eb12c5c7d51b13749c5e7607e5ab187b584e0bc35ac6a9b17e3a1bd717f' .
        'b4f7c6ffad48afad5fa1d44faef31554c2fce0f2dbc6a215761eb10e664bd353' .
        '156eb13da776b51c049d1ead133542cbdf8b5ffb124bbe82184bce9c0d9da611' .
        '0e47f69a40d3c365f9c2e3fc4178ac36deadd61bbc0817a8cf7cf5bf944c228b' .
        'e675888b05c84e';

    /** @var string $keypair_alice */
    private $keypair_alice;
    /** @var string $keypair_bob */
    private $keypair_bob;
    /** @var string $keypair_mallory */
    private $keypair_mallory;

    public function __construct()
    {
        parent::__construct();

        $this->keypair_alice = sodium_crypto_box_seed_keypair(str_repeat("\1", 32));
        $this->keypair_bob = sodium_crypto_box_seed_keypair(str_repeat("\2", 32));
        $this->keypair_mallory = sodium_crypto_box_seed_keypair(str_repeat("\3", 32));

        Encryption::$debug_fix_key = str_repeat("\0", 32);
        Encryption::$debug_fix_keypair = sodium_crypto_box_seed_keypair(str_repeat("\0", 32));
    }

    public function testEncrypt(): void
    {
        $encrypted = Encryption::encrypt(self::INPUT_STRING, $this->keypair_alice, [
            sodium_crypto_box_publickey($this->keypair_bob),
        ]);

        $this->assertEquals(self::ENCRYPTED_HEX, bin2hex($encrypted));
    }

    public function testEncryptStream(): void
    {
        // TODO
    }

    public function testDecrypt(): void
    {
        $encrypted = hex2bin(self::ENCRYPTED_HEX);
        $data = Encryption::decrypt($encrypted, $this->keypair_bob, $sender_public_key);

        $this->assertEquals(sodium_crypto_box_publickey($this->keypair_alice), $sender_public_key);
        $this->assertEquals(self::INPUT_STRING, $data);
    }

    public function testDecryptStream(): void
    {
        $encrypted = hex2bin(self::ENCRYPTED_HEX);
        $result = '';

        foreach (Encryption::decryptStream(
            [$encrypted], $this->keypair_bob, $sender_public_key
        ) as $i => $decoded_chunk) {
            $result .= $decoded_chunk;
        }

        $this->assertEquals(sodium_crypto_box_publickey($this->keypair_alice), $sender_public_key);
        $this->assertEquals(self::INPUT_STRING, $result);
    }

    public function testDecryptWithWrongKeypairFails(): void
    {
        $this->expectException(\Exception::class);

        $encrypted = hex2bin(self::ENCRYPTED_HEX);
        Encryption::decrypt($encrypted, $this->keypair_mallory);
    }
}
