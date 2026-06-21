<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\UserAuthProvider;
use App\Models\Otp;
use App\Models\Role;
use App\Mail\OtpMail;
use App\Services\FirebaseAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Exception;

class AuthController extends Controller
{
    public function __construct(private FirebaseAuthService $firebaseAuth)
    {
    }

    /**
     * Issue a new Sanctum token and return user data
     */
    private function issueToken(User $user, ?Request $request = null): array
    {
        try {
            $user->forceFill(['last_login' => now()])->save();
            $token = $user->createToken('auth_token');

            if ($request) {
                $token->accessToken->forceFill([
                    'device_name' => $request->input('device_name'),
                    'platform' => $request->input('platform'),
                    'platform_version' => $request->input('platform_version'),
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                ])->save();
            }

            return [
                'user' => $user->makeVisible(['profile_image_url', 'profile_pic_url', 'name']),
                'token' => $token->plainTextToken,
            ];
        } catch (Exception $e) {
            Log::error('IssueToken Error: ' . $e->getMessage());
            $token = $user->createToken('auth_token');
            return [
                'user' => $user->makeVisible(['profile_image_url', 'profile_pic_url', 'name']),
                'token' => $token->plainTextToken,
            ];
        }
    }

    private function validOtp(string $email, string $code): ?Otp
    {
        $record = Otp::where('email', strtolower(trim($email)))
            ->where('otp', trim($code))
            ->first();

        if (!$record || now()->gt($record->expires_at)) return null;
        return $record;
    }

    private function sendOtpTo(string $email, string $successMessage)
    {
        $email = strtolower(trim($email));
        $otp = (string) random_int(100000, 999999);

        try {
            Otp::updateOrCreate(
                ['email' => $email],
                ['otp' => $otp, 'expires_at' => now()->addMinutes(15)]
            );

            // Using failover mailer (Resend -> SMTP -> Log) to ensure delivery
            Mail::mailer('failover')->to($email)->send(new OtpMail($otp, $email));

            Log::info("OTP sent successfully via SMTP to: $email");
            return response()->json(['message' => $successMessage]);

        } catch (Exception $e) {
            Log::error('OTP Mail Error: ' . $e->getMessage());
            // Fallback to log for debugging if SMTP/Resend fails
            Log::info("FALLBACK: OTP for $email is $otp");

            // For development/local testing, we return success so they can check logs
            if (config('app.debug') || app()->environment('local')) {
                return response()->json([
                    'message' => $successMessage . ' (Check server logs for the code)'
                ]);
            }

            return response()->json(['message' => 'Email delivery failed. Please try again later.'], 500);
        }
    }

    private function verifiedFirebasePayload(Request $request): ?array
    {
        $request->validate([
            'firebase_id_token' => 'required_without:provider_token|string',
            'provider_token' => 'required_without:firebase_id_token|string',
        ]);

        $token = $request->input('firebase_id_token') ?: $request->input('provider_token');
        return $this->firebaseAuth->verifyIdToken($token);
    }

    private function firebaseProvider(array $payload): ?string
    {
        return $payload['firebase']['sign_in_provider'] ?? null;
    }

    private function appProviderFromFirebase(array $payload): string
    {
        return match ($this->firebaseProvider($payload)) {
            'google.com' => 'google',
            'facebook.com' => 'facebook',
            default => 'email',
        };
    }

    private function providerColumn(string $provider): string
    {
        return $provider === 'google' ? 'google_id' : 'facebook_id';
    }

    private function syncAuthProvider(User $user, string $provider, string $firebaseUid, ?string $email = null): void
    {
        UserAuthProvider::updateOrCreate(
            ['user_id' => $user->id, 'provider' => $provider],
            [
                'firebase_uid' => $firebaseUid,
                'email' => $email ? strtolower($email) : $user->email,
                'last_used_at' => now(),
            ]
        );
    }

    private function userRoleId(): int
    {
        return Role::firstOrCreate(['role_name' => 'user'])->id;
    }

    private function createUserFromFirebasePayload(array $payload, string $email): User
    {
        $provider = $this->appProviderFromFirebase($payload);
        $socialProvider = in_array($provider, ['google', 'facebook'], true) ? $provider : null;

        $userData = [
            'role_id' => $this->userRoleId(),
            'username' => $this->generateUniqueUsername($payload['name'] ?? explode('@', $email)[0]),
            'email' => $email,
            'password' => Hash::make(random_bytes(16)),
            'is_password_set' => $provider === 'email',
            'profile_image' => $payload['picture'] ?? null,
            'firebase_uid' => $payload['sub'],
            'social_provider' => $socialProvider,
            'social_id' => $socialProvider ? $payload['sub'] : null,
            'is_verified' => (bool) ($payload['email_verified'] ?? false),
            'status' => 'active',
        ];

        if ($socialProvider) {
            $userData[$this->providerColumn($socialProvider)] = $payload['sub'];
        }

        return User::create($userData);
    }

    private function findUserForFirebasePayload(array $payload, ?string $email = null, ?string $provider = null): ?User
    {
        $firebaseUid = $payload['sub'] ?? null;
        $provider ??= $this->appProviderFromFirebase($payload);

        // 1. Try finding by existing Firebase connection for this provider
        $providerLink = UserAuthProvider::where('provider', $provider)
            ->where('firebase_uid', $firebaseUid)
            ->first();

        if ($providerLink?->user) {
            return $providerLink->user;
        }

        // 2. Try finding by the primary firebase_uid
        if ($firebaseUid) {
            $user = User::where('firebase_uid', $firebaseUid)->first();
            if ($user) return $user;
        }

        // 3. Try finding by provider-specific legacy columns
        if (in_array($provider, ['google', 'facebook'], true) && $firebaseUid) {
            $column = $this->providerColumn($provider);
            $user = User::where($column, $firebaseUid)->first();
            if ($user) return $user;
        }

        // 4. Try finding by Email (IMPORTANT for linking different social accounts)
        if ($email) {
            $user = User::where('email', strtolower($email))->first();
            if ($user) return $user;
        }

        return null;
    }

    private function syncUserWithFirebasePayload(User $user, array $payload, string $provider): User
    {
        $firebaseUid = $payload['sub'];
        $email = !empty($payload['email']) ? strtolower($payload['email']) : $user->email;

        // Record this specific provider-to-user link in our provider table
        $this->syncAuthProvider($user, $provider, $firebaseUid, $email);

        // Keep the first Firebase UID we ever saw as the primary ID
        if (!$user->firebase_uid) {
            $user->firebase_uid = $firebaseUid;
        }

        $user->is_verified = (bool) ($payload['email_verified'] ?? $user->is_verified);

        if ($provider === 'email') {
            $user->is_password_set = true;
        }

        // Link Google/Facebook specifically so we can find them later
        if (in_array($provider, ['google', 'facebook'], true)) {
            $column = $this->providerColumn($provider);
            $user->$column = $firebaseUid;

            // Set the active social info if not set
            if (!$user->social_provider) {
                $user->social_provider = $provider;
                $user->social_id = $firebaseUid;
            }

            if (!$user->profile_image && ($payload['picture'] ?? null)) {
                $user->profile_image = $payload['picture'];
            }
        }

        $user->save();
        return $user;
    }

    private function ensureFirebaseEmailPasswordUser(User $user, string $password): bool
    {
        if ($user->firebase_uid) {
            return true;
        }

        $firebaseUid = $this->firebaseAuth->syncEmailPasswordUser($user->email, $password);
        if (!$firebaseUid) {
            return false;
        }

        $user->forceFill([
            'firebase_uid' => $firebaseUid,
            'is_password_set' => true,
        ])->save();

        return true;
    }

    public function register(Request $request)
    {
        $validated = $request->validate([
            'username' => 'required|string|max:32|unique:users,username',
            'email' => 'required|email|max:64|unique:users,email',
            'password' => 'required|min:8|max:64',
        ]);

        $email = strtolower($validated['email']);

        // 1. Create User in Backend
        $user = User::create([
            'role_id' => $this->userRoleId(),
            'username' => $validated['username'],
            'email' => $email,
            'password' => Hash::make($validated['password']),
            'is_password_set' => true,
            'status' => 'active',
        ]);

        // 2. Sync with Firebase in Background (Create account in Firebase so social linking works)
        try {
            $firebaseUid = $this->firebaseAuth->createEmailPasswordUser($email, $validated['password']);
            if ($firebaseUid) {
                $user->forceFill(['firebase_uid' => $firebaseUid])->save();
                $this->syncAuthProvider($user, 'email', $firebaseUid, $email);
            }
        } catch (Exception $e) {
            Log::error('Firebase Sync Error during Registration: ' . $e->getMessage());
        }

        $session = $this->issueToken($user, $request);
        return response()->json(['message' => 'Registered successfully', 'user' => $session['user'], 'token' => $session['token']], 201);
    }

    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email|max:64',
            'password' => 'required|string',
        ]);

        $email = strtolower($validated['email']);
        $user = User::where('email', $email)->first();

        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response()->json(['message' => 'Invalid email or password.'], 401);
        }

        if ($user->status !== 'active') {
            return response()->json(['message' => 'Account is ' . $user->status], 403);
        }

        // 3. Ensure User is synced with Firebase (if they were created before we added Firebase)
        try {
            if (!$user->firebase_uid) {
                $this->ensureFirebaseEmailPasswordUser($user, $validated['password']);
            }
        } catch (Exception $e) {
            Log::error('Firebase Sync Error during Login: ' . $e->getMessage());
            // Continue login even if sync fails
        }

        $session = $this->issueToken($user, $request);
        return response()->json(['message' => 'Login successful', 'user' => $session['user'], 'token' => $session['token']]);
    }

    public function verifyLegacyLogin(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email|max:64',
            'password' => 'required|min:6|max:64',
        ]);

        $user = User::where('email', strtolower($validated['email']))->first();
        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response()->json(['message' => 'Invalid email or password.'], 401);
        }

        if ($user->status !== 'active') {
            return response()->json(['message' => 'Account is ' . $user->status], 403);
        }

        $hadFirebaseUid = (bool) $user->firebase_uid;
        $firebaseSynced = $this->ensureFirebaseEmailPasswordUser($user, $validated['password']) && !$hadFirebaseUid;

        return response()->json([
            'message' => 'Legacy credentials verified.',
            'firebase_synced' => $firebaseSynced,
            'firebase_uid' => $user->firebase_uid,
        ]);
    }

    public function profile(Request $request)
    {
        $user = $request->user();
        return response()->json([
            'user' => $user->makeVisible(['profile_image_url', 'profile_pic_url', 'name']),
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()?->currentAccessToken()?->delete();
        return response()->json(['message' => 'Logged out successfully']);
    }

    public function checkEmail(Request $request)
    {
        $exists = User::where('email', strtolower($request->email))->exists();
        return response()->json(['exists' => $exists]);
    }

    public function checkUsername(Request $request)
    {
        $exists = User::where('username', strtolower($request->username))->exists();
        return response()->json(['exists' => $exists]);
    }

    public function forgotPassword(Request $request)
    {
        $request->validate(['email' => 'required|email']);
        $email = strtolower(trim($request->email));

        $user = User::where('email', $email)->first();
        if (!$user) return response()->json(['message' => 'No account found with that email address.'], 404);

        return $this->sendOtpTo($email, 'Verification code has been sent to your email.');
    }

    public function verifyCode(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'code' => 'required|string'
        ]);

        if (!$this->validOtp($request->email, $request->code)) {
            return response()->json(['message' => 'Invalid or expired verification code.'], 400);
        }

        return response()->json(['message' => 'Code verified successfully.']);
    }

    public function resetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'code' => 'required|string',
            'password' => 'required|min:8|confirmed',
        ]);

        $user = User::where('email', strtolower($request->email))->first();
        if (!$user || !$this->validOtp($request->email, $request->code)) return response()->json(['message' => 'Invalid request.'], 400);
        $user->password = Hash::make($request->password);
        $user->is_password_set = true;
        $user->save();

        Otp::where('email', strtolower($request->email))->delete();

        return response()->json(['message' => 'Password reset successfully.']);
    }

    public function updateProfile(Request $request)
    {
        $user = $request->user();
        $validated = $request->validate([
            'username' => 'required|string|max:32|unique:users,username,' . $user->id,
            'bio' => 'nullable|string|max:255',
            'profile_image' => 'nullable|image|max:2048',
        ]);

        $user->username = $validated['username'];
        $user->bio = $validated['bio'] ?? $user->bio;

        if ($request->hasFile('profile_image')) {
            $this->deleteStoredProfileImage($user->profile_image);
            $user->profile_image = $request->file('profile_image')->store('profile_images', 'supabase_images');
        }

        $user->save();
        return response()->json([
            'message' => 'Updated.',
            'user' => $user->makeVisible(['profile_image_url', 'profile_pic_url', 'name']),
        ]);
    }

    private function deleteStoredProfileImage(?string $profileImage): void
    {
        if (!$profileImage || filter_var($profileImage, FILTER_VALIDATE_URL)) {
            return;
        }

        Storage::disk('supabase_images')->delete($profileImage);
        Storage::disk('public')->delete($profileImage);
    }

    public function socialLogin(Request $request)
    {
        $request->validate(['provider' => 'required|in:google,facebook', 'provider_token' => 'required|string']);
        $payload = $this->verifiedFirebasePayload($request);

        if (!$payload || empty($payload['sub'])) return response()->json(['message' => 'Verification failed.'], 401);

        $expectedProvider = $request->provider === 'google' ? 'google.com' : 'facebook.com';
        if ($this->firebaseProvider($payload) !== $expectedProvider) {
            return response()->json(['message' => 'Firebase provider does not match request provider.'], 422);
        }

        // Try to get email from Payload first, then from Request
        $email = $payload['email'] ?? $request->input('email');
        if ($email) {
            $email = strtolower(trim($email));
        }

        Log::info("Social Login processing: Provider={$request->provider}, Email=" . ($email ?? 'NULL'));

        $user = $this->findUserForFirebasePayload($payload, $email, $request->provider);

        if ($user) {
            if ($user->status !== 'active') return response()->json(['message' => 'Forbidden'], 403);

            // If user exists but email is null in DB (unlikely but possible), update it if we have it now
            if (!$user->email && $email) {
                $user->email = $email;
            }

            $user = $this->syncUserWithFirebasePayload($user, $payload, $request->provider);
        } else {
            // Support users without emails (e.g. some Facebook accounts)
            // But if we HAVE an email from providerData (sent via request), use it!
            $finalEmail = $email ?: ($request->provider . '_' . $payload['sub'] . '@social.musicapp');

            $user = User::create([
                'role_id' => $this->userRoleId(),
                'username' => $this->generateUniqueUsername($payload['name'] ?? ($email ? explode('@', $email)[0] : 'user')),
                'email' => $finalEmail,
                'password' => Hash::make(random_bytes(16)),
                'is_password_set' => false,
                'profile_image' => $payload['picture'] ?? null,
                'firebase_uid' => $payload['sub'],
                $this->providerColumn($request->provider) => $payload['sub'],
                'social_provider' => $request->provider,
                'social_id' => $payload['sub'],
                'is_verified' => (bool) ($payload['email_verified'] ?? false),
                'status' => 'active',
            ]);
            $this->syncAuthProvider($user, $request->provider, $payload['sub'], $finalEmail);
        }

        $session = $this->issueToken($user, $request);
        return response()->json(['message' => 'Login successful.', 'user' => $session['user'], 'token' => $session['token']]);
    }

    private function generateUniqueUsername(string $name): string
    {
        $base = preg_replace('/[^a-z0-9_]/', '', strtolower($name)) ?: 'user';
        $username = $base;
        $count = 1;
        while (User::where('username', $username)->exists()) {
            $username = $base . $count++;
        }
        return $username;
    }

    public function securityOverview(Request $request)
    {
        try {
            $user = $request->user();
            $currentTokenId = $user->currentAccessToken()?->id;

            $tokens = $user->tokens()->orderByDesc('created_at')->get();

            $sessions = $tokens->map(function ($token) use ($currentTokenId) {
                return [
                    'id' => $token->id,
                    'device_name' => $token->device_name ?? 'Device',
                    'platform' => $token->platform ?? 'Unknown',
                    'platform_version' => $token->platform_version,
                    'ip_address' => $token->ip_address,
                    'is_current' => $currentTokenId === $token->id,
                    'created_at' => $token->created_at?->toIso8601String(),
                    'last_used_at' => $token->last_used_at?->toIso8601String(),
                ];
            });

            return response()->json([
                'active_sessions' => $sessions,
                'login_history' => $sessions->take(20)->values(),
            ]);
        } catch (Exception $e) {
            Log::error('SecurityOverview Error: ' . $e->getMessage());
            return response()->json(['message' => 'Failed to load security data'], 500);
        }
    }

    public function revokeSession(Request $request, $tokenId)
    {
        $user = $request->user();
        $token = $user->tokens()->where('id', $tokenId)->first();

        if (!$token) return response()->json(['message' => 'Session not found.'], 404);

        $token->delete();
        return response()->json(['message' => 'Session revoked.']);
    }

    public function revokeAllSessions(Request $request)
    {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'All sessions revoked.']);
    }

    public function sendSecurityCode(Request $request)
    {
        return $this->sendOtpTo($request->user()->email, 'Security code sent.');
    }

    public function changePassword(Request $request)
    {
        $user = $request->user();
        $validated = $request->validate([
            'current_password' => 'nullable|string',
            'code' => 'nullable|string|size:6',
            'password' => 'required|min:8|confirmed',
        ]);

        $currentPassword = $validated['current_password'] ?? null;
        $code = $validated['code'] ?? null;
        $currentPasswordOk = $currentPassword && Hash::check($currentPassword, $user->password);
        $codeOk = $code && $this->validOtp($user->email, $code);
        $authOk = $currentPasswordOk || $codeOk;

        if (!$authOk) return response()->json(['message' => 'Invalid authentication.'], 422);

        // Update password only in backend database
        $user->password = Hash::make($validated['password']);
        $user->is_password_set = true;
        $user->save();

        if ($code) Otp::where('email', strtolower($user->email))->delete();

        return response()->json(['message' => 'Password changed successfully.']);
    }

    public function connectSocialAccount(Request $request)
    {
        $user = $request->user();
        $request->validate(['provider' => 'required|in:google,facebook', 'provider_token' => 'required|string']);

        $profile = $this->firebaseProfile($request);
        if (!$profile) return response()->json(['message' => 'Verification failed.'], 401);

        $column = $this->providerColumn($request->provider);
        if (User::where($column, $profile['id'])->where('id', '!=', $user->id)->exists()) {
            return response()->json(['message' => 'Already connected to another account.'], 409);
        }

        if (User::where('firebase_uid', $profile['id'])->where('id', '!=', $user->id)->exists()) {
            return response()->json(['message' => 'Firebase account is already connected to another user.'], 409);
        }

        if (!$user->firebase_uid) {
            $user->firebase_uid = $profile['id'];
        }
        $user->$column = $profile['id'];
        $user->social_provider = $request->provider;
        $user->social_id = $profile['id'];
        $user->save();

        return response()->json(['message' => 'Connected.', 'user' => $user]);
    }

    public function disconnectSocialAccount(Request $request)
    {
        $user = $request->user();
        $request->validate(['provider' => 'required|in:google,facebook']);

        $column = $request->provider === 'google' ? 'google_id' : 'facebook_id';
        $user->$column = null;
        if ($user->social_provider === $request->provider) {
            $remainingProvider = $request->provider === 'google'
                ? ($user->facebook_id ? 'facebook' : null)
                : ($user->google_id ? 'google' : null);

            $user->social_provider = $remainingProvider;
            $user->social_id = $remainingProvider ? $user->{$this->providerColumn($remainingProvider)} : null;
        }
        $user->save();

        return response()->json(['message' => 'Disconnected.', 'user' => $user]);
    }

    private function firebaseProfile(Request $request): ?array
    {
        $payload = $this->verifiedFirebasePayload($request);
        if (!$payload || empty($payload['sub'])) {
            return null;
        }

        $expectedProvider = $request->provider === 'google' ? 'google.com' : 'facebook.com';
        if ($this->firebaseProvider($payload) !== $expectedProvider) {
            return null;
        }

        return [
            'id' => $payload['sub'],
            'email' => $payload['email'] ?? null,
            'name' => $payload['name'] ?? null,
            'picture' => $payload['picture'] ?? null,
            'email_verified' => (bool) ($payload['email_verified'] ?? false),
        ];
    }
}
