<?php

declare(strict_types=1);

namespace Saltpack;

use MessagePack\BufferUnpacker;

use React\Stream\DuplexStreamInterface;
use React\Stream\WritableStreamInterface;

use Evenement\EventEmitter;
use React\EventLoop\LoopInterface;
use InvalidArgumentException;
use BadMethodCallException;

final class EncryptStream extends EventEmitter implements DuplexStreamInterface
{
    private $in_buffer = '';
    private $written_header = false;

    private $readable = true;
    private $writable = true;
    private $closing = false;
    private $listening = false;

    private $payload_key;
    private $ephemeral_keypair;
    private $public_key;
    private $private_key;

    private $keypair;
    private $sender_public_key;
    private $sender_private_key;

    private $recipients;
    private $header;

    private $index = 0;

    public function __construct(string $keypair, array $recipients_keys)
    {
        // 1. Generate a random 32-byte payload key.
        $this->payload_key = Encryption::$debug_fix_key ?? random_bytes(32);

        // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
        $this->ephemeral_keypair = Encryption::$debug_fix_keypair ?? sodium_crypto_box_keypair();
        $this->public_key = sodium_crypto_box_publickey($this->ephemeral_keypair);
        $this->private_key = sodium_crypto_box_secretkey($this->ephemeral_keypair);

        $this->keypair = $keypair ?? $this->ephemeral_keypair;

        $this->sender_public_key = sodium_crypto_box_publickey($this->keypair);
        $this->sender_private_key = sodium_crypto_box_secretkey($this->keypair);

        $index = 0;
        $this->recipients = array_map(function (string $recipient_key) use (&$index) {
            return EncryptedMessageRecipient::create($recipient_key, $this->private_key, $this->payload_key, $index++);
        }, $recipients_keys);

        $this->header = EncryptedMessageHeader::create(
            $this->public_key, $this->payload_key, $this->sender_public_key, $this->recipients
        );

        foreach ($this->recipients as $recipient) {
            /** @var EncryptedMessageRecipient $recipient */
            $recipient->generateMacKeyForSender($this->header->hash, $this->private_key, $this->sender_private_key);
        }

        $this->resume();
    }

    public function isReadable()
    {
        return $this->readable;
    }

    public function isWritable()
    {
        return $this->writable;
    }

    public function pause()
    {
        if ($this->listening) {
            $this->listening = false;
        }
    }

    public function resume()
    {
        if (!$this->listening && $this->readable) {
            $this->listening = true;
        }
    }

    public function write($data)
    {
        if (!$this->writable) {
            return false;
        }

        if (!$this->written_header) {
            $this->emit('data', [$this->header->encoded]);
            $this->written_header = true;
        }

        $this->in_buffer .= $data;

        while (strlen($this->in_buffer) > Encryption::CHUNK_LENGTH) {
            $chunk = substr($this->in_buffer, 0, Encryption::CHUNK_LENGTH);
            $this->in_buffer = substr($this->in_buffer, Encryption::CHUNK_LENGTH);

            // This is never the final payload as there must be additional data in `in_buffer`

            $payload = EncryptedMessagePayload::create(
                $this->header, $this->payload_key, $chunk, $this->index, /* final */ false
            );

            $this->emit('data', [$payload->encoded]);
            $this->index++;
        }

        return true;
    }

    public function end($data = null)
    {
        if (is_string($data)) {
            $this->write($data);
        }

        if (!$this->writable) {
            return;
        }

        while (strlen($this->in_buffer) >= Encryption::CHUNK_LENGTH) {
            $chunk = substr($this->in_buffer, 0, Encryption::CHUNK_LENGTH);
            $this->in_buffer = substr($this->in_buffer, Encryption::CHUNK_LENGTH);

            $final = strlen($this->in_buffer) <= 0;
            $payload = EncryptedMessagePayload::create(
                $this->header, $this->payload_key, $chunk, $this->index, $final
            );

            $this->emit('data', [$payload->encoded]);
            $this->index++;
        }

        if (strlen($this->in_buffer) > 0) {
            $chunk = $this->in_buffer;
            $this->in_buffer = '';

            $final = strlen($this->in_buffer) <= 0;
            $payload = EncryptedMessagePayload::create(
                $this->header, $this->payload_key, $chunk, $this->index, $final
            );

            $this->emit('data', [$payload->encoded]);
            $this->index++;
        }

        $this->closing = true;

        $this->readable = false;
        $this->writable = false;
        $this->pause();
    }

    public function close()
    {
        if (!$this->writable && !$this->closing) {
            return;
        }

        $this->closing = false;

        $this->readable = false;
        $this->writable = false;

        $this->emit('close');
        $this->pause();
        $this->removeAllListeners();
    }

    public function pipe(WritableStreamInterface $dest, array $options = array())
    {
        return Util::pipe($this, $dest, $options);
    }
}
