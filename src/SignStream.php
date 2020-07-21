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

final class SignStream extends EventEmitter implements DuplexStreamInterface
{
    private $in_buffer = '';
    private $written_header = false;

    private $readable = true;
    private $writable = true;
    private $closing = false;
    private $listening = false;

    private $private_key;
    private $header;

    private $index = 0;

    public function __construct(string $keypair)
    {
        $public_key = sodium_crypto_sign_publickey($keypair);
        $this->private_key = sodium_crypto_sign_secretkey($keypair);

        $this->header = SignedMessageHeader::create($public_key, true);

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

        while (strlen($this->in_buffer) > Signing::CHUNK_LENGTH) {
            $chunk = substr($this->in_buffer, 0, Signing::CHUNK_LENGTH);
            $this->in_buffer = substr($this->in_buffer, Signing::CHUNK_LENGTH);

            // This is never the final payload as there must be additional data in `in_buffer`

            $payload = SignedMessagePayload::create(
                $this->header, $this->private_key, $chunk, $this->index, /* final */ false
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

        while (strlen($this->in_buffer) >= Signing::CHUNK_LENGTH) {
            $chunk = substr($this->in_buffer, 0, Signing::CHUNK_LENGTH);
            $this->in_buffer = substr($this->in_buffer, Signing::CHUNK_LENGTH);

            $final = strlen($this->in_buffer) <= 0;
            $payload = SignedMessagePayload::create(
                $this->header, $this->private_key, $chunk, $this->index, $final
            );

            $this->emit('data', [$payload->encoded]);
            $this->index++;
        }

        if (strlen($this->in_buffer) > 0) {
            $chunk = $this->in_buffer;
            $this->in_buffer = '';

            $final = strlen($this->in_buffer) <= 0;
            $payload = SignedMessagePayload::create(
                $this->header, $this->private_key, $chunk, $this->index, $final
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
