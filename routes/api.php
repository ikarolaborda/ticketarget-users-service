<?php

declare(strict_types=1);

use App\Http\Controllers\LoginController;
use App\Http\Controllers\MeController;
use App\Http\Controllers\RegisterController;
use App\Http\Controllers\UpdatePasswordController;
use App\Http\Controllers\UpdateProfileController;
use Illuminate\Support\Facades\Route;

Route::post('/auth/register', RegisterController::class)->name('auth.register');
Route::post('/auth/login', LoginController::class)->middleware('throttle:10,1')->name('auth.login');
Route::get('/auth/me', MeController::class)->name('auth.me');
Route::put('/auth/profile', UpdateProfileController::class)->name('auth.profile');
Route::put('/auth/password', UpdatePasswordController::class)->name('auth.password');
