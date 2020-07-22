php-saltpack
===

A PHP implementation of [Keybase](https://keybase.io)'s [Saltpack](https://saltpack.org)
encrypted/signed messaging format.

php-saltpack implements version 2.0 of Saltpack. All message types (encryption, attached signing,
detached signing and signcryption) are supported.

Installation
---

php-saltpack is published to Packagist. GMP and Sodium are required.

```
composer require samuelthomas2774/saltpack
```

React is required for streaming.

```
composer require react/stream
```

Encryption
---

`Encryption::encryptAndArmor` encrypts a string and returns the ASCII-armored encrypted data.

`Encryption::encrypt` accepts the same arguments as `Encryption::encryptAndArmor` but returns a string without armor.

```php
use Saltpack\Encryption;

$plaintext = '...';
$sender_keypair = sodium_crypto_box_keypair();
$recipients_keys = [
    sodium_crypto_box_publickey(sodium_crypto_box_keypair()),
];

$encrypted = Encryption::encryptAndArmor($plaintext, $sender_keypair, $recipients_keys);

// $encrypted === 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P ...
```

php-saltpack also supports streaming encryption with `Encryption::encryptAndArmorStream`
(or `Encryption::encryptStream` for encrypting without armor).

```php
use Saltpack\Encryption;

$sender_keypair = sodium_crypto_box_keypair();
$recipients_keys = [
    sodium_crypto_box_publickey(sodium_crypto_box_keypair()),
];

$stream = Encryption::encryptAndArmorStream($sender_keypair, $recipients_keys);

// Write the encrypted and armored data to stdout
$stdout = new WritableResourceStream(STDOUT, $loop);
$stream->pipe($stdout);

$stream->end('...');
```

Messages can be decrypted with `Encryption::dearmorAndDecrypt` (or `Encryption::decrypt` if the message isn't armored).

```php
use Saltpack\Encryption;

$encrypted = 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P ...';
$recipient_keypair = sodium_crypto_box_keypair();

// If you know the sender's public key you can pass it to Encryption::dearmorAndDecrypt and it will throw if it doesn't match
$sender_key = sodium_crypto_box_publickey(sodium_crypto_box_keypair());

try {
    // $sender_key is passed by reference - if it is set this will throw if it doesn't match, otherwise it will be set to the sender's public key
    $decrypted = Encryption::dearmorAndDecrypt($encrypted, $recipient_keypair, $sender_key);

    // If you didn't pass the sender's public key you should check it now
    if ($sender_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }

    // $decrypted === '...'
} catch (\Saltpack\Exceptions\DecryptionError $err) {
    // Message could not be decrypted
} catch (\Saltpack\Exceptions\VerifyError $err) {
    // Message could not be verified
} catch (\Throwable $err) {
    //
}
```

Decryption also supports streaming with `Encryption::dearmorAndDecryptStream` or `Encryption::decryptStream`.

```php
use Saltpack\Encryption;

$recipient_keypair = sodium_crypto_box_keypair();

// If you know the sender's public key you can pass it to Encryption::dearmorAndDecryptStream and it will emit an error if it doesn't match
$sender_key = sodium_crypto_box_publickey(sodium_crypto_box_keypair());

$stream = Encryption::dearmorAndDecryptStream($recipient_keypair, $sender_key);

$stream->on('end', () => {
    // If you didn't pass the sender's public key you should check it now
    if ($stream->sender_public_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }
});
$stream->on('error', function (\Exception $err) {
    //
});

// Write the encrypted and armored data to stdout
$stdout = new WritableResourceStream(STDOUT, $loop);
$stream->pipe($stdout);

$stream->end('BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P ...');
```

Signing
---

`Signing::signAndArmor` signs a string and returns the ASCII-armored signed data.

`Signing::sign` accepts the same arguments as `Signing::signAndArmor` but returns a string without armor.

```php
use Saltpack\Signing;

$plaintext = '...';
$signing_keypair = sodium_crypto_sign_keypair();

$signed = Signing::signAndArmor($plaintext, $signing_keypair);

// $signed === 'BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...
```

Streaming is supported with `Signing::signAndArmorStream` or `Signing::signStream`.

```php
use Saltpack\Signing;

$signing_keypair = sodium_crypto_sign_keypair();

$stream = Signing::signAndArmorStream($signing_keypair);

// Write the encrypted and armored data to stdout
$stdout = new WritableResourceStream(STDOUT, $loop);
$stream->pipe($stdout);

$stream->end('...');
```

Signed messages can be verified and read with `Signing::dearmorAndVerify` or `Signing::verify`.

```php
use Saltpack\Signing;

$signed = 'BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...';

// If you know the sender's public key you can pass it to Signing::dearmorAndVerify and it will throw if it doesn't match
$sender_key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

try {
    // $sender_key is passed by reference - if it is set this will throw if it doesn't match, otherwise it will be set to the sender's public key
    $verified = Signing::dearmorAndVerify($signed, $sender_key);

    // If you didn't pass the sender's public key you should check it now
    if ($sender_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }

    // $verified === '...'
} catch (\Saltpack\Exceptions\VerifyError $err) {
    // Message could not be verified
} catch (\Throwable $err) {
    //
}
```

Reading signed messages also supports streaming with `Signing::dearmorAndVerifyStream` or `Signing::verifyStream`.

```php
use Saltpack\Signing;

// If you know the sender's public key you can pass it to Signing::dearmorAndVerifyStream and it will throw if it doesn't match
$sender_key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

$stream = Signing::dearmorAndVerifyStream($sender_key);

$stream->on('end', () => {
    // If you didn't pass the sender's public key you should check it now
    if ($stream->public_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }
});
$stream->on('error', function (\Exception $err) {
    //
});

// Write the verified data to stdout
$stdout = new WritableResourceStream(STDOUT, $loop);
$stream->pipe($stdout);

$stream->end('BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...');
```

Detached signing
---

`Signing::signDetachedAndArmor` signs a string and returns the ASCII-armored signature.

`Signing::signDetached` accepts the same arguments as `Signing::signDetachedAndArmor` but returns a string
without armor.

> Detached signing/verifying does not support streaming yet.

```php
use Saltpack\Signing;

$plaintext = '...';
$signing_keypair = sodium_crypto_sign_keypair();

$signed = Signing::signDetachedAndArmor($plaintext, $signing_keypair);

// $signed === 'BEGIN SALTPACK DETACHED SIGNATURE. kYM5h1pg6qz9UMn j6G9T0tZQlxoky3 0YoKQ4s21IrFv3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...
```

Detached signatures can be verified with `Signing::dearmorAndVerifyDetached` or `Signing::verifyDetached`.

```php
use Saltpack\Signing;

$signed = 'BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...';
$plaintext = '...';

// If you know the sender's public key you can pass it to dearmorAndVerifyDetached and it will throw if it doesn't match
$sender_key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

try {
    // $sender_key is passed by reference - if it is set this will throw if it doesn't match, otherwise it will be set to the sender's public key
    Signing::dearmorAndVerifyDetached($signature, $plaintext, $sender_key);

    // If you didn't pass the sender's public key you should check it now
    if ($sender_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }
} catch (\Saltpack\Exceptions\VerifyError $err) {
    // Message could not be verified
} catch (\Throwable $err) {
    //
}
```

Signcryption
---

> Signcryption is very similar to Saltpack's usual encryption format, but:
>
> - The sender uses an Ed25519 signing key instead of an X25519 encryption key,
> - A symmetric key can be provided for a group of recipients instead of each recipient having their own encryption
>     key (this is not implemented by php-saltpack yet, though the internal APIs are there), and
> - Messages are not repudiable, which means anyone who has a copy of the message and a decryption key can verify it's
>     authenticity, not just intended recipients.

`Signcryption::encryptAndArmor` encrypts a string and returns the ASCII-armored signcrypted data.

`Signcryption::encrypt` accepts the same arguments as `Signcryption::encryptAndArmor` but returns a string
without armor.

```php
use Saltpack\Signcryption;

$plaintext = '...';
$sender_keypair = sodium_crypto_sign_keypair();
$recipients_keys = [
    // TODO: how can a recipient identifier and symmetric key be provided?
    sodium_crypto_box_publickey(sodium_crypto_box_keypair()),
];

$signcrypted = Signcryption::encryptAndArmor($plaintext, $sender_keypair, $recipients_keys);

// $signcrypted === 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHnhYI5G UXZkLqLqVvhmpfZ rss3XwjQHK0irv7 rNIcmnvmn5RTzTR OPZLLRr1s0DEZtS ...
```

Streaming is supported with `Signcryption::encryptAndArmorStream` or (`Signcryption::encryptStream` for encrypting
without armor).

```php
use Saltpack\Signcryption;

$sender_keypair = sodium_crypto_sign_keypair();
$recipients_keys = [
    // TODO: how can a recipient identifier and symmetric key be provided?
    sodium_crypto_box_publickey(sodium_crypto_box_keypair()),
];

$stream = Signcryption::encryptAndArmorStream($sender_keypair, $recipients_keys);

// Write the verified data to stdout
$stdout = new WritableResourceStream(STDOUT, $loop);
$stream->pipe($stdout);

$stream->end('...');
```

Messages can be decrypted with `Signcryption::dearmorAndDecrypt` (or `Signcryption::decrypt` if the message
isn't armored).

```php
use Saltpack\Signcryption;

$encrypted = 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHnhYI5G UXZkLqLqVvhmpfZ rss3XwjQHK0irv7 rNIcmnvmn5RTzTR OPZLLRr1s0DEZtS ...';
// TODO: how can a recipient identifier and symmetric key be provided?
// How can multiple keys be provided (as a recipient may have multiple shared symmetric keys that may be used for this message)
$recipient_keypair = sodium_crypto_box_keypair();

// If you know the sender's public key you can pass it to Signcryption::dearmorAndDecrypt and it will throw if it doesn't match
$sender_key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

try {
    // $sender_key is passed by reference - if it is set this will throw if it doesn't match, otherwise it will be set to the sender's public key
    $decrypted = Signcryption::dearmorAndDecrypt($encrypted, $recipient_keypair, $sender_key);

    // If you didn't pass the sender's public key you should check it now
    if ($sender_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }

    // $decrypted === '...'
} catch (\Saltpack\Exceptions\DecryptionError $err) {
    // Message could not be decrypted
} catch (\Saltpack\Exceptions\VerifyError $err) {
    // Message could not be verified
} catch (\Throwable $err) {
    //
}
```

Decryption also supports streaming with `Signcryption::dearmorAndDecryptStream` or `Signcryption::decryptStream`.

```php
use Saltpack\Signcryption;

// TODO: how can a recipient identifier and symmetric key be provided?
// How can multiple keys be provided (as a recipient may have multiple shared symmetric keys that may be used for this message)
$recipient_keypair = sodium_crypto_box_keypair();

// If you know the sender's public key you can pass it to Signcryption::dearmorAndDecryptStream and it will emit an error if it doesn't match
$sender_key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

$stream = Signcryption::dearmorAndDecryptStream($recipient_keypair, $sender_key);

$stream->on('end', () => {
    // If you didn't pass the sender's public key you should check it now
    if ($stream->sender_public_key !== hex2bin('...')) {
        throw new Exception('Sender public key doesn\'t match');
    }
});
$stream->on('error', function (\Exception $err) {
    //
});

// Write the encrypted and armored data to stdout
$stdout = new WritableResourceStream(STDOUT, $loop);
$stream->pipe($stdout);

$stream->end('BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHnhYI5G UXZkLqLqVvhmpfZ rss3XwjQHK0irv7 rNIcmnvmn5RTzTR OPZLLRr1s0DEZtS ...');
```

Additional notes
---

- php-saltpack always chunks input data to 1 MB payloads.
- php-saltpack is fully tested with [node-saltpack](https://gitlab.fancy.org.uk/samuel/node-saltpack).
- php-saltpack is partially tested with [Keybase](https://github.com/keybase/saltpack):
    - Encrypted messages created by node-saltpack and php-saltpack can be decrypted with Keybase.
    - Signcrypted messages created by node-saltpack and php-saltpack can be decrypted with Keybase.
    - Signed messages created by Keybase can be verified with node-saltpack and php-saltpack.
    - Signed messages created by node-saltpack and php-saltpack can be read by Keybase.

License
---

php-saltpack is released under the [MIT license](LICENSE). Saltpack is designed by the Keybase developers,
and uses [NaCl](https://nacl.cr.yp.to) for crypto and [MessagePack](https://msgpack.org) for binary encoding.
node-saltpack and php-saltpack's armoring implementation is based on
[saltpack-ruby](https://github.com/ged/saltpack-ruby).
