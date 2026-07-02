<?php

declare(strict_types=1);

use App\Http\Controllers\LoginController;
use App\Http\Controllers\MeController;
use App\Http\Controllers\RegisterController;
use Illuminate\Support\Facades\Route;

Route::post('/auth/register', RegisterController::class)->name('auth.register');
Route::post('/auth/login', LoginController::class)->middleware('throttle:10,1')->name('auth.login');
Route::get('/auth/me', MeController::class)->name('auth.me');
