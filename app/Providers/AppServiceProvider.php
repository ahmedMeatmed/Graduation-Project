<?php

namespace App\Providers;

use App\Policies\SignaturePolicy;
use App\Policies\UserPolicy;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
        Gate::define('create-signature',[SignaturePolicy::class,'create']);
        Gate::define('delete-signature',[SignaturePolicy::class,'delete']);
        Gate::define('create-user',[UserPolicy::class,'create']);
        Gate::define('update-user',[UserPolicy::class,'update']);
        Gate::define('delete-user',[UserPolicy::class,'delete']);
    }
}
