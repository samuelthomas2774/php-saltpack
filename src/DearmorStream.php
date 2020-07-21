<?php

declare(strict_types=1);

namespace Saltpack;

use React\Stream\DuplexStreamInterface;
use React\Stream\WritableStreamInterface;

use Evenement\EventEmitter;
use React\EventLoop\LoopInterface;
use InvalidArgumentException;

final class DearmorStream extends EventEmitter implements DuplexStreamInterface
{
    private $in_buffer = '';
    private $out_buffer = '';

    private $readable = true;
    private $writable = true;
    private $closing = false;
    private $listening = false;

    private $options;
    private $header = null;
    private $header_info = null;
    private $footer = null;

    public function __construct(array $options = [])
    {
        $options = array_merge(Armor::DEFAULT_OPTIONS, $options);

        $this->options = $options;

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

        if (!$this->options['raw'] && $this->header === null) {
            $this->in_buffer .= $data;

            $index = strpos($this->in_buffer, '.');
            if ($index === false) return true;

            $this->header = substr($this->in_buffer, 0, $index);
            $data = substr($this->in_buffer, $index + 1);
            $this->in_buffer = '';

            if (!preg_match(Armor::HEADER_REGEX, $this->header, $header_match)) {
                throw new Exceptions\InvalidArmorFraming('Invalid header');
            }

            $this->header_info = [
                'message_type' => $header_match[3],
                'app_name' => $header_match[2],
            ];

            if (Armor::$debug) echo 'Read header: ' . $this->header . PHP_EOL;
        }

        if (!$this->options['raw'] && $this->footer !== null) {
            $this->footer .= $data;

            $remaining_index = strpos($this->footer, '.');
            if ($remaining_index !== false) {
                $this->footer = substr($this->footer, 0, $remaining_index);
                return true;
            }
        }

        if (!$this->options['raw'] && $this->footer === null) {
            $index = strpos($data, '.');
            if ($index !== false) {
                $this->footer = substr($data, $index + 1);
                $data = substr($data, 0, $index);
                $this->in_buffer .= str_replace(['>', "\n", "\r", "\t", ' '], '', $data);

                $remaining_index = strpos($this->footer, '.');
                if ($remaining_index !== false) {
                    $this->footer = substr($this->footer, 0, $remaining_index);
                    return true;
                }

                return true;
            }
        }

        if ($this->options['raw'] || $this->footer === null) {
            $this->in_buffer .= str_replace(['>', "\n", "\r", "\t", ' '], '', $data);

            while (strlen($this->in_buffer) > $this->options['char_block_size']) {
                $block = substr($this->in_buffer, 0, $this->options['char_block_size']);
                $this->in_buffer = substr($this->in_buffer, $this->options['char_block_size']);

                $this->emit('data', [Armor::decodeBlock($block, $this->options['alphabet'], $this->options['shift'])]);
            }
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

        while (strlen($this->in_buffer) > $this->options['char_block_size']) {
            $block = substr($this->in_buffer, 0, $this->options['char_block_size']);
            $this->in_buffer = substr($this->in_buffer, $this->options['char_block_size']);

            $this->emit('data', [Armor::decodeBlock($block, $this->options['alphabet'], $this->options['shift'])]);
        }

        if (strlen($this->in_buffer) > 0) {
            $this->emit('data', [Armor::decodeBlock(
                $this->in_buffer, $this->options['alphabet'], $this->options['shift']
            )]);
            $this->in_buffer = '';
        }

        if (!$this->options['raw'] && $this->footer === null) {
            throw new Exceptions\InvalidArmorFraming('Input stream doesn\'t contain a valid header and footer');
        }

        if (!$this->options['raw']) {
            if (!preg_match(Armor::FOOTER_REGEX, $this->footer, $match)) {
                throw new Exceptions\InvalidArmorFraming('Invalid footer');
            }
            if ($this->header_info['message_type'] !== $match[3] ||
                $this->header_info['app_name'] !== $match[2]
            ) {
                throw new Exceptions\InvalidArmorFraming('Footer doesn\'t match header');
            }

            if (Armor::$debug) echo 'Read footer: ' . $this->footer . PHP_EOL;
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
