<?php

use App\Models\User;
use App\Models\Otp;
use App\Services\FirebaseAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Sanctum;

uses(RefreshDatabase::class);

test('login creates a backend user when firebase account has no local row', function () {
    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldReceive('verifyIdToken')
            ->once()
            ->with('valid-firebase-token')
            ->andReturn([
                'sub' => 'firebase-uid-123',
                'email' => 'newuser@example.com',
                'email_verified' => true,
                'name' => 'New User',
                'firebase' => [
                    'sign_in_provider' => 'password',
                ],
            ]);
    });

    $response = $this->postJson('/api/login', [
        'email' => 'newuser@example.com',
        'firebase_id_token' => 'valid-firebase-token',
    ]);

    $response
        ->assertOk()
        ->assertJsonPath('user.email', 'newuser@example.com')
        ->assertJsonPath('user.firebase_uid', 'firebase-uid-123')
        ->assertJsonStructure(['token']);

    $this->assertDatabaseHas('roles', ['role_name' => 'user']);
    $this->assertDatabaseHas('users', [
        'email' => 'newuser@example.com',
        'firebase_uid' => 'firebase-uid-123',
        'username' => 'newuser',
        'is_password_set' => true,
    ]);
});

test('login links existing backend user to firebase uid', function () {
    $role = \App\Models\Role::firstOrCreate(['role_name' => 'user']);

    User::create([
        'role_id' => $role->id,
        'username' => 'existing',
        'email' => 'existing@example.com',
        'password' => bcrypt('password'),
        'status' => 'active',
    ]);

    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldReceive('verifyIdToken')
            ->once()
            ->with('valid-firebase-token')
            ->andReturn([
                'sub' => 'firebase-existing-uid',
                'email' => 'existing@example.com',
                'email_verified' => true,
                'firebase' => [
                    'sign_in_provider' => 'password',
                ],
            ]);
    });

    $response = $this->postJson('/api/login', [
        'email' => 'existing@example.com',
        'firebase_id_token' => 'valid-firebase-token',
    ]);

    $response
        ->assertOk()
        ->assertJsonPath('user.email', 'existing@example.com')
        ->assertJsonPath('user.firebase_uid', 'firebase-existing-uid');

    $this->assertDatabaseCount('users', 1);
});

test('legacy verification syncs backend password account to firebase when uid is missing', function () {
    $role = \App\Models\Role::firstOrCreate(['role_name' => 'user']);

    User::create([
        'role_id' => $role->id,
        'username' => 'legacy',
        'email' => 'legacy@example.com',
        'password' => bcrypt('secret123'),
        'is_password_set' => true,
        'status' => 'active',
    ]);

    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldReceive('syncEmailPasswordUser')
            ->once()
            ->with('legacy@example.com', 'secret123')
            ->andReturn('firebase-legacy-uid');
    });

    $response = $this->postJson('/api/login/legacy-verify', [
        'email' => 'legacy@example.com',
        'password' => 'secret123',
    ]);

    $response
        ->assertOk()
        ->assertJsonPath('firebase_synced', true)
        ->assertJsonPath('firebase_uid', 'firebase-legacy-uid');

    $this->assertDatabaseHas('users', [
        'email' => 'legacy@example.com',
        'firebase_uid' => 'firebase-legacy-uid',
    ]);
});

test('legacy verification does not sync firebase when database password is invalid', function () {
    $role = \App\Models\Role::firstOrCreate(['role_name' => 'user']);

    User::create([
        'role_id' => $role->id,
        'username' => 'wrongpass',
        'email' => 'wrongpass@example.com',
        'password' => bcrypt('secret123'),
        'status' => 'active',
    ]);

    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldNotReceive('syncEmailPasswordUser');
    });

    $this->postJson('/api/login/legacy-verify', [
        'email' => 'wrongpass@example.com',
        'password' => 'badpass123',
    ])->assertUnauthorized();

    $this->assertDatabaseHas('users', [
        'email' => 'wrongpass@example.com',
        'firebase_uid' => null,
    ]);
});

test('reset password creates firebase account when backend user has no firebase uid', function () {
    $role = \App\Models\Role::firstOrCreate(['role_name' => 'user']);

    User::create([
        'role_id' => $role->id,
        'username' => 'resetuser',
        'email' => 'reset@example.com',
        'password' => bcrypt('oldpass123'),
        'status' => 'active',
    ]);

    Otp::create([
        'email' => 'reset@example.com',
        'otp' => '123456',
        'expires_at' => now()->addMinutes(15),
    ]);

    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldReceive('syncEmailPasswordUser')
            ->once()
            ->with('reset@example.com', 'newpass123')
            ->andReturn('firebase-reset-uid');
        $mock->shouldNotReceive('updatePassword');
    });

    $response = $this->postJson('/api/reset-password', [
        'email' => 'reset@example.com',
        'code' => '123456',
        'password' => 'newpass123',
        'password_confirmation' => 'newpass123',
    ]);

    $response->assertOk()->assertJsonPath('message', 'Password reset.');

    $this->assertDatabaseHas('users', [
        'email' => 'reset@example.com',
        'firebase_uid' => 'firebase-reset-uid',
        'is_password_set' => true,
    ]);
    $this->assertDatabaseMissing('otps', ['email' => 'reset@example.com']);
});

test('change password syncs missing firebase account before updating firebase password', function () {
    $role = \App\Models\Role::firstOrCreate(['role_name' => 'user']);

    $user = User::create([
        'role_id' => $role->id,
        'username' => 'changepass',
        'email' => 'change@example.com',
        'password' => bcrypt('oldpass123'),
        'status' => 'active',
    ]);

    Sanctum::actingAs($user);

    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldReceive('syncEmailPasswordUser')
            ->once()
            ->with('change@example.com', 'oldpass123')
            ->andReturn('firebase-change-uid');
        $mock->shouldReceive('updatePasswordWithEmailPassword')
            ->once()
            ->with('change@example.com', 'oldpass123', 'newpass123')
            ->andReturn(true);
        $mock->shouldNotReceive('updatePassword');
    });

    $response = $this->postJson('/api/user/change-password', [
        'current_password' => 'oldpass123',
        'password' => 'newpass123',
        'password_confirmation' => 'newpass123',
    ]);

    $response->assertOk()->assertJsonPath('message', 'Password changed.');

    $this->assertDatabaseHas('users', [
        'email' => 'change@example.com',
        'firebase_uid' => 'firebase-change-uid',
        'is_password_set' => true,
    ]);
});

test('change password with current password updates existing firebase account using web api credentials', function () {
    $role = \App\Models\Role::firstOrCreate(['role_name' => 'user']);

    $user = User::create([
        'role_id' => $role->id,
        'username' => 'existingfire',
        'email' => 'existingfire@example.com',
        'password' => bcrypt('oldpass123'),
        'firebase_uid' => 'firebase-existing-uid',
        'status' => 'active',
    ]);

    Sanctum::actingAs($user);

    $this->mock(FirebaseAuthService::class, function ($mock) {
        $mock->shouldReceive('updatePasswordWithEmailPassword')
            ->once()
            ->with('existingfire@example.com', 'oldpass123', 'newpass123')
            ->andReturn(true);
        $mock->shouldNotReceive('syncEmailPasswordUser');
        $mock->shouldNotReceive('updatePassword');
    });

    $response = $this->postJson('/api/user/change-password', [
        'current_password' => 'oldpass123',
        'password' => 'newpass123',
        'password_confirmation' => 'newpass123',
    ]);

    $response->assertOk()->assertJsonPath('message', 'Password changed.');
});
