<?php

use Illuminate\Http\Request;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UploadController;
use App\Http\Controllers\AlbumController;
use Illuminate\Support\Facades\Route;


// Public Routes
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/login/legacy-verify', [AuthController::class, 'verifyLegacyLogin']);
Route::post('/check-email', [AuthController::class, 'checkEmail']);
Route::post('/check-username', [AuthController::class, 'checkUsername']);
Route::post('/social-login', [AuthController::class, 'socialLogin']);
Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
Route::post('/verify-code', [AuthController::class, 'verifyCode']);
Route::post('/reset-password', [AuthController::class, 'resetPassword']);
Route::get('/genres', [UploadController::class, 'listGenres']);
Route::get('/tracks/public', [UploadController::class, 'publicTracks']);
Route::get('/search', [UploadController::class, 'search']);
Route::get('/users/{id}', [UploadController::class, 'showUser']);
Route::get('/albums/public', [AlbumController::class, 'publicAlbums']);
Route::get('/genres/{id}/tracks', [UploadController::class, 'genreTracks']);

// Protected Routes
Route::middleware('auth:sanctum')->group(function () {

    Route::get('/me', [AuthController::class, 'profile']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/user/update', [AuthController::class, 'updateProfile']);
    Route::post('/user/security-code', [AuthController::class, 'sendSecurityCode']);
    Route::post('/user/change-password', [AuthController::class, 'changePassword']);
    Route::post('/user/social/connect', [AuthController::class, 'connectSocialAccount']);
    Route::post('/user/social/disconnect', [AuthController::class, 'disconnectSocialAccount']);
    Route::get('/user/security', [AuthController::class, 'securityOverview']);
    Route::delete('/user/security/sessions', [AuthController::class, 'revokeAllSessions']);
    Route::delete('/user/security/sessions/{tokenId}', [AuthController::class, 'revokeSession']);

    // Tracks
    Route::post('/tracks/upload', [UploadController::class, 'upload']);
    Route::get('/tracks/radio', [UploadController::class, 'radio']);
    Route::get('/tracks/new-releases', [UploadController::class, 'newReleases']);
    Route::get('/tracks', [UploadController::class, 'index']);
    Route::get('/tracks/{id}', [UploadController::class, 'show']);
    Route::post('/tracks/{id}', [UploadController::class, 'update']);
    Route::put('/tracks/{id}', [UploadController::class, 'update']);
    Route::delete('/tracks/{id}', [UploadController::class, 'destroy']);

    // Albums
    Route::get('/albums/new-releases', [AlbumController::class, 'newReleases']);
    Route::get('/albums/{id}/tracks', [AlbumController::class, 'tracks']);
    Route::apiResource('albums', AlbumController::class)->except(['create', 'edit']);


});
