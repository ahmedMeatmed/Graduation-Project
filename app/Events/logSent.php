<?php

namespace App\Events;

use Illuminate\Broadcasting\Channel;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class logSent implements ShouldBroadcast
{
    use Dispatchable, InteractsWithSockets, SerializesModels, ShouldBroadcast;

    public $log;

    /**
     * Create a new event instance.
     */
    public function __construct($log)
    {
        //
        $this->log = $log;
    }

    /**
     * Get the channels the event should broadcast on.
     *
     * @return array<int, \Illuminate\Broadcasting\Channel>
     */
    public function broadcastOn(): array
    {
        return [
            new Channel('logs-channel'),
        ];
    }
    public function broadcastWith()
    {
        return [
            'log' => $this->log,
        ];
    }


}
