<?php

use App\Models\User;
use App\Services\FirebaseAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
