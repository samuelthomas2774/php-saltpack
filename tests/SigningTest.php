<?php

declare(strict_types=1);

namespace SaltpackTests;

use PHPUnit\Framework\TestCase;
use Saltpack\Armor;
use Saltpack\Signing;
use Saltpack\SignedMessageHeader;
use Saltpack\SignStream;
use Saltpack\VerifyStream;
use Saltpack\Exceptions;

final class SigningTest extends TestCase
{
    const INPUT_STRING = 'Two roads diverged in a yellow wood, and sorry I could not travel both' . "\n" .
        'and be one traveller, long I stood, and looked down one as far as I' . "\n" .
        'could, to where it bent in the undergrowth.';

    // Signed with a hardcoded keypair
    const SIGNATURE_HEADER_HEX = 'c45295a873616c747061636b92020001c4203b6a27bcceb6a42d62a3a8d02a6f' .
        '0d73653215771de243a63ac048a18b59da29c420000000000000000000000000' .
        '0000000000000000000000000000000000000000';
    const SIGNED_HEX = 'c45295a873616c747061636b92020001c4203b6a27bcceb6a42d62a3a8d02a6f' .
        '0d73653215771de243a63ac048a18b59da29c420000000000000000000000000' .
        '000000000000000000000000000000000000000093c3c4404a77380837fb4ec6' .
        '2480e76c59b735a6287e85b54afe7793531ff70076c51fc23b1f078e6700b85b' .
        'eb9fc091d69c8826b5268765b7eded317d943fed99bb560fc4b654776f20726f' .
        '61647320646976657267656420696e20612079656c6c6f7720776f6f642c2061' .
        '6e6420736f727279204920636f756c64206e6f742074726176656c20626f7468' .
        '0a616e64206265206f6e652074726176656c6c65722c206c6f6e672049207374' .
        '6f6f642c20616e64206c6f6f6b656420646f776e206f6e652061732066617220' .
        '617320490a636f756c642c20746f2077686572652069742062656e7420696e20' .
        '74686520756e64657267726f7774682e';

    const DETACHED_SIGNATURE_HEADER_HEX = 'c45295a873616c747061636b92020002c4203b6a27bcceb6a42d62a3a8d02a6f' .
        '0d73653215771de243a63ac048a18b59da29c420000000000000000000000000' .
        '0000000000000000000000000000000000000000';
    const DETACHED_SIGNATURE_HEX = 'c45295a873616c747061636b92020002c4203b6a27bcceb6a42d62a3a8d02a6f' .
        '0d73653215771de243a63ac048a18b59da29c420000000000000000000000000' .
        '0000000000000000000000000000000000000000c4403d452b27bfc69543e20c' .
        'bf3a139fd689450f26e4084660f66090de422f2e438931efd159c9101c99e070' .
        'f3de277330b51940a7583f8c925085b1f86f38693f06';

    /** @var string $keypair */
    private $keypair;

    public function __construct()
    {
        parent::__construct();

        $this->keypair = sodium_crypto_sign_seed_keypair(str_repeat("\0", 32));
        SignedMessageHeader::$debug_fix_nonce = str_repeat("\0", 32);
    }

    public function testSign(): void
    {
        $signed = Signing::sign(self::INPUT_STRING, $this->keypair);

        $this->assertEquals(self::SIGNED_HEX, bin2hex($signed));
        $this->assertEquals(self::SIGNATURE_HEADER_HEX,
            substr(bin2hex($signed), 0, strlen(self::SIGNATURE_HEADER_HEX)));
    }

    public function testSignStream(): void
    {
        $options = [];
        $result = '';

        $stream = new SignStream($this->keypair);

        $stream->on('data', function (string $data) use (&$result) {
            $result .= $data;
        });

        foreach (str_split(self::INPUT_STRING, 3) as $in) {
            $stream->write($in);
        }

        $stream->end();

        $this->assertEquals(self::SIGNED_HEX, bin2hex($result));
    }

    public function testVerify(): void
    {
        $public_key = sodium_crypto_sign_publickey($this->keypair);

        $signed = hex2bin(self::SIGNED_HEX);
        $data = Signing::verify($signed, $public_key);

        $this->assertEquals(self::INPUT_STRING, $data);
    }

    public function testVerifyStream(): void
    {
        $public_key = sodium_crypto_sign_publickey($this->keypair);

        $signed = hex2bin(self::SIGNED_HEX);
        $result = '';

        $stream = new VerifyStream($public_key);

        $stream->on('data', function (string $data) use (&$result) {
            $result .= $data;
        });

        foreach (str_split($signed, 3) as $in) {
            $stream->write($in);
        }

        $stream->end();

        $this->assertEquals(self::INPUT_STRING, $result);
    }

    public function testVerifyWithWrongPublicKeyFails(): void
    {
        $this->expectException(Exceptions\VerifyError::class);

        $public_key = sodium_crypto_sign_publickey($this->keypair);
        $public_key[0] = '0';

        $signed = hex2bin(self::SIGNED_HEX);
        Signing::verify($signed, $public_key);
    }

    public function testSignDetachedHeader(): void
    {
        $signed = Signing::signDetached(self::INPUT_STRING, $this->keypair, $debug);

        $this->assertEquals(self::DETACHED_SIGNATURE_HEADER_HEX, bin2hex($debug[0]->encoded));
    }

    public function testSignDetached(): void
    {
        $signed = Signing::signDetached(self::INPUT_STRING, $this->keypair);

        $this->assertEquals(self::DETACHED_SIGNATURE_HEX, bin2hex($signed));
    }

    public function testVerifyDetached(): void
    {
        $public_key = sodium_crypto_sign_publickey($this->keypair);

        $signature = hex2bin(self::DETACHED_SIGNATURE_HEX);
        Signing::verifyDetached($signature, self::INPUT_STRING, $public_key);

        $this->assertEquals(1, 1);
    }

    public function testVerifyDetachedWithWrongPublicKeyFails(): void
    {
        $this->expectException(Exceptions\VerifyError::class);

        $public_key = sodium_crypto_sign_publickey($this->keypair);
        $public_key[0] = '0';

        $signature = hex2bin(self::DETACHED_SIGNATURE_HEX);
        Signing::verifyDetached($signature, self::INPUT_STRING, $public_key);
    }
}
