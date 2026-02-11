<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Redis;

class RedisListener extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'redis-listener';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $batchSize = 50;
        $logs = [];

        $this->info("Listening for Redis logs...");

        while (true) {

            // Wait for ONE log (blocking)
            $data = Redis::brpop('ids_logs', 0);

            $logJson = $data[1];
            $logs[] = json_decode($logJson, true);

            $this->info("Received log: " . count($logs));

            // When batch is full
            if (count($logs) >= $batchSize)
            // if (1)
                {

                $this->info("Processing 50 logs...");

                foreach ($logs as $log) {
                    // Example: save to DB
                    // LogModel::create($log);
                    print_r($log);
                }

                // Reset batch
                $logs = [];
            }
        }
    }
}
