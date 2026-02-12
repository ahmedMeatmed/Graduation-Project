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
            $logs = Redis::brpop('ids_logs', 0);
            $alerts = Redis::brpop('ids_alerts', 0);

            $Fetchedlogs[] = json_decode($logs[1], true);
            $Fetchedalerts[] = json_decode($alerts[1], true);

            $this->info("Received log: " . count($Fetchedlogs));
            $this->info("Received log: " . count($Fetchedalerts));
            print_r($Fetchedalerts);

            // When batch is full
            if (count($Fetchedlogs) >= $batchSize)
                {

                $this->info("Processing 50 Fetchedlogs...");

                foreach ($Fetchedlogs as $log) {
                    // Example: save to DB
                    // LogModel::create($log);
                    // print_r($log);
                }

                // Reset batch
                $Fetchedlogs = [];
            }
        }
    }
}
