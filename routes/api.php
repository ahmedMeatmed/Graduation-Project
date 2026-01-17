<?php

// use App\Http\Controllers\TestController;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


use App\Http\Controllers\LoginController;
use App\Http\Controllers\Api\v1\IdsController;
use App\Http\Controllers\Api\v1\LogController;
use App\Http\Controllers\Api\v1\UserController;
use App\Http\Controllers\Api\v1\AlertController;
use App\Http\Controllers\Api\v1\SettingController;
use App\Http\Controllers\Api\v1\SignatureController;

Route::post('/login', [LoginController::class, 'login'])->name('login');

Route::middleware('auth:sanctum')->prefix('v1')->group(function () {

    Route::apiResource('users', UserController::class);

    Route::apiResource('logs', LogController::class);

    Route::apiResource('signatures', SignatureController::class);

    Route::apiResource('alerts', AlertController::class);

    Route::apiResource('settings', SettingController::class);

    Route::post('signatures/search', [SignatureController::class, 'search']);

    Route::post('Run', [IdsController::class, 'index']);
    
    Route::post('Stop', [IdsController::class, 'destroy']);

    Route::post('/logout', [LoginController::class, 'logout']);
});
