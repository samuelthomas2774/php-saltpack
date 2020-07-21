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

final class VerifyStream extends EventEmitter implements DuplexStreamInterface
{
    private $readable = true;
    private $writable = true;
    private $closing = false;
    private $listening = false;

    private $unpacker;

    private $public_key;
    private $header = null;
    private $payload_key = null;
    private $recipient = null;
    private $sender_public_key = null;
    private $last_payload = null;
    private $index = -1;

    public function __construct(string $public_key)
    {
        $this->public_key = $public_key;
        $this->unpacker = new BufferUnpacker();

        $this->resume();
    }

    public function __get(string $key)
    {
        if ($key === 'sender_public_key') {
            if ($this->sender_public_key === null) throw new BadMethodCallException('Header hasn\'t been decoded yet');
            return $this->sender_public_key;
        }

        throw new BadMethodCallException('Unknown property "' . $key . '"');
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

        $this->unpacker->append($data);

        $messages = $this->unpacker->tryUnpack();

        if ($this->header === null && count($messages) > 0) {
            $header_data = array_shift($messages);
            $this->header = SignedMessageHeader::decode($header_data, true);
        }

        foreach ($messages as $message) {
            $this->index++;

            if ($this->last_payload) {
                if ($this->last_payload->final) {
                    throw new Exceptions\InvalidFinalFlag('Found payload with invalid final flag, message extended?');
                }

                $this->emit('data', [$this->last_payload->data]);
            }

            $payload = SignedMessagePayload::decode($message, true);
            $payload->verify($this->header, $this->public_key, $this->index);

            $this->last_payload = $payload;
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

        if ($this->last_payload) {
            if (!$this->last_payload->final) {
                throw new Exceptions\InvalidFinalFlag('Found payload with invalid final flag, message truncated?');
            }

            $this->emit('data', [$this->last_payload->data]);
        } else {
            throw new Exceptions\VerifyError('No signed payloads, message truncated?');
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
