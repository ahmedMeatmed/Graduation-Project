<?php

namespace App\Console\Commands;

use App\Events\logSent;
use App\Events\alertSent;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Redis;
use ParagonIE\Sodium\Core\Curve25519\Fe;

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
            $this->info("Received alert: " . count($Fetchedalerts));
            // print_r($Fetchedalerts);

            // When batch is full
            if (count($Fetchedlogs) >= $batchSize){
                $this->info("Processing 50 Fetchedlogs...");
                foreach ($Fetchedlogs as $log) {
                    broadcast(new logSent($log));
                }

                // Reset batch
                $Fetchedlogs = [];
            }

            if(count($Fetchedalerts) > 0){
                $this->info("Processing 1 Fetchedalerts...");
                foreach ($Fetchedalerts as $alert) {
                    broadcast(new alertSent($alert));
                }

                // Reset batch
                $Fetchedalerts = [];

            }
        }
    }
}
