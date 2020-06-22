<?php

declare(strict_types=1);

namespace SaltpackTests;

use PHPUnit\Framework\TestCase;
use Saltpack\Armor;
use Saltpack\Signing;
use Saltpack\SignedMessageHeader;

final class SigningTest extends TestCase
{
    const INPUT_STRING = 'Two roads diverged in a yellow wood, and sorry I could not travel both' . "\n" .
        'and be one traveller, long I stood, and looked down one as far as I' . "\n" .
        'could, to where it bent in the undergrowth.';

    // Signed with a hardcoded keypair
    const SIGNED_ARMORED = 'BEGIN SALTPACK MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM ' .
        'CnBX5wO3tOv7bWQ C0ZjZmZwkVc0000 000000000000000 00000000xTSC6Pg rfGb2LrM9GBjenP w3DX3Ds8TxgDfKJ ' .
        'opD87cg3NkGYdfr YcvCu8lglIAFuU2 MKITUw0xscRdmtJ M1v1jgyZjEH5Vem dFbYdN5s9bkJE42 hEUFOKNdklXPbnW ' .
        'N7ftTO2L4pqwnl4 5s9QAyu8GLIeOCh nGSD3XNOUPToxH3 Pelc42Xz5oOVMI3 c2ScE8gRgTQ9UAM VXnut3siWpTSEqQ ' .
        'VHhLbdfUDCmKdIQ QKXoeeJBRilOtbN gckxla11c4v6Qzw tlPxv7p6y2e8N6i Paehy2YQ8IFggor 7CMMLWrnzrU40vL ' .
        'vCFTlwsK8G3Xeok f8UrxgICsgJapXL xe. END SALTPACK MESSAGE.';
    const SIGNED_HEX = 'c45295a873616c747061636b92020001c4203b6a27bcceb6a42d62a3a8d02a6f' .
        '0d73653215771de243a63ac048a18b59da29d920000000000000000000000000' .
        '000000000000000000000000000000000000000093c3c4409437e3d24a86c389' .
        '44458705d8a9410b37eb65c163c2070c0907f0251379a4a2f9083e7baa00be6f' .
        'b4558d56b3fc861832fb98cdb46ec039d2f46082ebf6fa08d9b654776f20726f' .
        '61647320646976657267656420696e20612079656c6c6f7720776f6f642c2061' .
        '6e6420736f727279204920636f756c64206e6f742074726176656c20626f7468' .
        '0a616e64206265206f6e652074726176656c6c65722c206c6f6e672049207374' .
        '6f6f642c20616e64206c6f6f6b656420646f776e206f6e652061732066617220' .
        '617320490a636f756c642c20746f2077686572652069742062656e7420696e20' .
        '74686520756e64657267726f7774682e';

    const DETACHED_SIGNATURE_ARMORED = 'BEGIN SALTPACK MESSAGE. kYM5h1pg6qz9UMn j6G9T0tZQlxoky3 0YoKQ4s21IrFv3B ' .
        'kmdpuvqpO3t2QdM CnBX5wO3tOv7bWQ C0ZjZmZwkVc0000 000000000000000 00000001GzTLjk5 Ttisc5wVwXdGuuL ' .
        'gp2AM0dwVcjFToE PddQafkHFkvFole iXj55me8KV5302a IORauTnukaCk2eA ReNSnzn. END SALTPACK MESSAGE.';
    const DETACHED_SIGNATURE_HEX = 'c45295a873616c747061636b92020002c4203b6a27bcceb6a42d62a3a8d02a6f' .
        '0d73653215771de243a63ac048a18b59da29d920000000000000000000000000' .
        '0000000000000000000000000000000000000000c440bf27a9aa7201dfe9f39c' .
        '8dd5becdeeeb430fd79d13dd0da80ffab41f4444dee626d53abae94290026664' .
        'd452fdc00d9bd1b96a4fc85e21fb08cfed90e16ff40b';

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
        $armored = Armor::armor($signed);

        $this->assertEquals(self::SIGNED_ARMORED, $armored);
        $this->assertEquals(self::SIGNED_HEX, bin2hex($signed));
    }

    public function testSignStream(): void
    {
        // TODO
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

        foreach (Signing::verifyStream([$signed], $public_key) as $i => $decoded_chunk) {
            $result .= $decoded_chunk;
        }

        $this->assertEquals(self::INPUT_STRING, $result);
    }

    public function testVerifyWithWrongPublicKeyFails(): void
    {
        $this->expectException(\Exception::class);

        $public_key = sodium_crypto_sign_publickey($this->keypair);
        $public_key[0] = '0';

        $signed = hex2bin(self::SIGNED_HEX);
        Signing::verify($signed, $public_key);
    }

    public function testSignDetached(): void
    {
        $signed = Signing::signDetached(self::INPUT_STRING, $this->keypair);
        $armored = Armor::armor($signed);

        $this->assertEquals(self::DETACHED_SIGNATURE_ARMORED, $armored);
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
        $this->expectException(\Exception::class);

        $public_key = sodium_crypto_sign_publickey($this->keypair);
        $public_key[0] = '0';

        $signature = hex2bin(self::DETACHED_SIGNATURE_HEX);
        Signing::verifyDetached($signature, self::INPUT_STRING, $public_key);
    }
}
