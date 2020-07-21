<?php

declare(strict_types=1);

namespace Saltpack;

use React\Stream\DuplexStreamInterface;
use React\Stream\WritableStreamInterface;

use Evenement\EventEmitter;
use React\EventLoop\LoopInterface;
use InvalidArgumentException;

final class ArmorStream extends EventEmitter implements DuplexStreamInterface
{
    private $in_buffer = '';
    private $out_buffer = '';

    private $readable = true;
    private $writable = true;
    private $closing = false;
    private $listening = false;

    private $options;
    private $header;
    private $footer;
    private $written_header = false;
    private $words = 0;

    public function __construct(array $options = [])
    {
        $options = array_merge(Armor::DEFAULT_OPTIONS, $options);

        $this->options = $options;

        $app = $options['app_name'] ? ' ' . $options['app_name'] : '';
        $this->header = 'BEGIN' . $app . ' SALTPACK ' . $options['message_type'] . '. ';
        $this->footer = '. END' . $app . ' SALTPACK ' . $options['message_type'] . '.';

        if ($options['raw']) {
            $this->written_header = true;
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
            $this->emit('data', [$this->header]);
            $this->written_header = true;
        }

        $this->in_buffer .= $data;

        while (strlen($this->in_buffer) > $this->options['block_size']) {
            $block = substr($this->in_buffer, 0, $this->options['block_size']);
            $this->in_buffer = substr($this->in_buffer, $this->options['block_size']);

            $this->out_buffer .= Armor::encodeBlock($block, $this->options['alphabet'], $this->options['shift']);
        }

        if ($this->options['raw']) {
            while (strlen($this->out_buffer) > 43) {
                $this->emit('data', [substr($this->out_buffer, 0, 43) . ' ']);
                $this->out_buffer = substr($this->out_buffer, 43);
            }
        } else {
            while (strlen($this->out_buffer) > 15) {
                $word = substr($this->out_buffer, 0, 15);
                $this->out_buffer = substr($this->out_buffer, 15);
                $this->words++;

                if ($this->words >= 200) {
                    $this->emit('data', [$word . "\n"]);
                    $this->words = 0;
                } else {
                    $this->emit('data', [$word . ' ']);
                }
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

        if (strlen($this->in_buffer) > 0) {
            $this->out_buffer .= Armor::encodeBlock(
                $this->in_buffer, $this->options['alphabet'], $this->options['shift']
            );
            $this->in_buffer = '';
        }

        if ($this->options['raw']) {
            while (strlen($this->out_buffer) > 43) {
                $this->emit('data', [substr($this->out_buffer, 0, 43) . ' ']);
                $this->out_buffer = substr($this->out_buffer, 43);
            }
        } else {
            while (strlen($this->out_buffer) > 15) {
                $word = substr($this->out_buffer, 0, 15);
                $this->out_buffer = substr($this->out_buffer, 15);
                $this->words++;

                if ($this->words >= 200) {
                    $this->emit('data', [$word . "\n"]);
                    $this->words = 0;
                } else {
                    $this->emit('data', [$word . ' ']);
                }
            }
        }

        if (strlen($this->out_buffer) > 0) {
            $this->emit('data', [$this->out_buffer]);
        }

        if (!$this->options['raw']) {
            $this->emit('data', [$this->footer]);
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
