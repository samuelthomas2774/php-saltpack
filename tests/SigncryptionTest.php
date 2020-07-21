<?php

declare(strict_types=1);

namespace SaltpackTests;

use PHPUnit\Framework\TestCase;
use Saltpack\Armor;
use Saltpack\Signcryption;
use Saltpack\SigncryptedMessageHeader;
use Saltpack\Exceptions;

final class SigncryptionTest extends TestCase
{
    const INPUT_STRING = 'Two roads diverged in a yellow wood, and sorry I could not travel both' . "\n" .
        'and be one traveller, long I stood, and looked down one as far as I' . "\n" .
        'could, to where it bent in the undergrowth.';

    // Encrypted with a hardcoded keypair
    const ENCRYPTED_HEX = 'c4b896a873616c747061636b92020003c4205bf55c73b82ebe22be80f3430667' .
        'af570fae2556a6415e6b30d4065300aa947dc43082818f5a22d20865c91ea58d' .
        '3d7b089d276f291464f06a5ea7ec112d5e2e87a96b18d53be0f72a454cd78226' .
        'e7f502d49192c420b7e814fc879ff6cc22f84fcb0f8df163322d7c81281eb552' .
        '57d7e7bfce8703bbc430d39daa6727cbe03f88442d7c49e74d3dfda0351d4168' .
        'df28886c75d64c72d1197519f59eee015bebbde222569f92950192c5010678aa' .
        '3d7d9526938b9512fc67a5d99d6f71c86725d2406e090569b5feda4594a6048b' .
        '356c97bb0798f32921e41bd96b5c07cdcb35b805e49535667373b4ad42d121aa' .
        'eb9ef1d55ef22f70a6e7410b9133f8e5e94bcf6b96d671ba1015f3255aa9f6a3' .
        'c6a2944c7569ae2c0269698ddd8dfcce59dc2fcc8b370b3df76afb4fe9606f57' .
        '352baf62f718a37ca0e4b8bc50d85aa49db9919e3908c3d600ff84cd0c65395e' .
        '3f62a5288e0e65b46a039db37a0c53416a31015c30a5209bcd31a862f0180d8d' .
        '9b4aedc587eb97aad8f89fdaaf7a13e71f23ecf6657def54a8f4e56c641c8cd6' .
        'd8540dcd88e5c8d8f5d4e79782db8516c53bee1e3689d089fb46c8de1bd95950' .
        '9a87d52ec3';

    /** @var string $keypair_alice Ed25519 signing keypair */
    private $keypair_alice;
    /** @var string $keypair_bob X25519 encryption keypair */
    private $keypair_bob;
    /** @var string $keypair_mallory X25519 encryption keypair */
    private $keypair_mallory;

    public function __construct()
    {
        parent::__construct();

        // With signcryption the sender *signs the message* with their Ed25519 key, and *encrypts for recipients'*
        // Curve25519 keys - so Alice, the sender, uses a signing key and Bob, the recipient, uses an encryption key
        $this->keypair_alice = sodium_crypto_sign_seed_keypair(str_repeat("\1", 32));

        $this->keypair_bob = sodium_crypto_box_seed_keypair(str_repeat("\2", 32));
        $this->keypair_mallory = sodium_crypto_box_seed_keypair(str_repeat("\3", 32));

        Signcryption::$debug_fix_key = str_repeat("\0", 32);
        Signcryption::$debug_fix_keypair = sodium_crypto_box_seed_keypair(str_repeat("\0", 32));
    }

    public function testEncrypt(): void
    {
        $encrypted = Signcryption::encrypt(self::INPUT_STRING, $this->keypair_alice, [
            sodium_crypto_box_publickey($this->keypair_bob),
        ]);

        $this->assertEquals(self::ENCRYPTED_HEX, bin2hex($encrypted));
    }

    public function testEncryptStream(): void
    {
        $options = [];
        $result = '';

        $stream = Signcryption::encryptStream($this->keypair_alice, [
            sodium_crypto_box_publickey($this->keypair_bob),
        ]);

        $stream->on('data', function (string $data) use (&$result) {
            $result .= $data;
        });

        foreach (str_split(self::INPUT_STRING, 3) as $in) {
            $stream->write($in);
        }

        $stream->end();

        $this->assertEquals(self::ENCRYPTED_HEX, bin2hex($result));
    }

    public function testDecrypt(): void
    {
        $encrypted = hex2bin(self::ENCRYPTED_HEX);
        $data = Signcryption::decrypt($encrypted, $this->keypair_bob, $sender_public_key);

        $this->assertEquals(sodium_crypto_sign_publickey($this->keypair_alice), $sender_public_key);
        $this->assertEquals(self::INPUT_STRING, $data);
    }

    public function testDecryptStream(): void
    {
        $encrypted = hex2bin(self::ENCRYPTED_HEX);
        $result = '';

        $stream = Signcryption::decryptStream($this->keypair_bob);

        $stream->on('data', function (string $data) use (&$result) {
            $result .= $data;
        });

        foreach (str_split($encrypted, 3) as $in) {
            $stream->write($in);
        }

        $stream->end();

        $this->assertEquals(sodium_crypto_sign_publickey($this->keypair_alice), $stream->sender_public_key);
        $this->assertEquals(self::INPUT_STRING, $result);
    }

    public function testDecryptWithWrongKeypairFails(): void
    {
        $this->expectException(Exceptions\DecryptionError::class);

        $encrypted = hex2bin(self::ENCRYPTED_HEX);
        Signcryption::decrypt($encrypted, $this->keypair_mallory);
    }
}
