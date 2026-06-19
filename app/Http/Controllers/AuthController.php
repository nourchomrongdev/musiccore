<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Otp;
use App\Mail\OtpMail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\ValidationException;
use Exception;

class AuthController extends Controller
{
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
            // Fallback: issue token without extra fields if migration not run
            $token = $user->createToken('auth_token');
            return [
                'user' => $user->makeVisible(['profile_image_url', 'profile_pic_url', 'name']),
                'token' => $token->plainTextToken,
            ];
        }
    }

    private function validOtp(string $email, string $code): ?Otp
    {
        $record = Otp::where('email', strtolower($email))
            ->where('otp', $code)
            ->first();

        if (!$record || now()->gt($record->expires_at)) return null;
        return $record;
    }

    private function sendOtpTo(string $email, string $successMessage)
    {
        $email = strtolower($email);
        $otp = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        Otp::updateOrCreate(
            ['email' => $email],
            ['otp' => $otp, 'expires_at' => now()->addMinutes(15)]
        );

        try {
            Mail::to($email)->send(new OtpMail($otp, $email));
        } catch (Exception $e) {
            Log::error('Failed to send OTP email: ' . $e->getMessage());
            return response()->json(['message' => 'Failed to send email.'], 500);
        }

        return response()->json(['message' => $successMessage]);
    }

    private function verifySocialToken(string $provider, string $token): ?array
    {
        if (!in_array($provider, ['google', 'facebook'], true)) return null;

        $projectId = config('services.firebase.project_id');
        if (!$projectId) return null;

        $segments = explode('.', $token);
        if (count($segments) !== 3) return null;

        [$encodedHeader, $encodedPayload, $encodedSignature] = $segments;
        $header = json_decode(base64_decode(strtr($encodedHeader, '-_', '+/')), true);
        $payload = json_decode(base64_decode(strtr($encodedPayload, '-_', '+/')), true);
        $signature = base64_decode(strtr($encodedSignature, '-_', '+/'));

        if (!$header || !$payload || !$signature || ($header['alg'] ?? null) !== 'RS256') return null;

        $certs = Cache::remember('firebase_certs', 21600, function () {
            return Http::get('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')->json();
        });

        $kid = $header['kid'] ?? null;
        if (!$kid || empty($certs[$kid])) return null;

        if (openssl_verify($encodedHeader . '.' . $encodedPayload, $signature, $certs[$kid], OPENSSL_ALGO_SHA256) !== 1) return null;

        if (($payload['aud'] ?? null) !== $projectId || ($payload['iss'] ?? null) !== 'https://securetoken.google.com/' . $projectId || ($payload['exp'] ?? 0) < time()) return null;

        return [
            'id' => $payload['sub'],
            'email' => $payload['email'],
            'name' => $payload['name'] ?? null,
            'picture' => $payload['picture'] ?? null,
        ];
    }

    public function register(Request $request)
    {
        $validated = $request->validate([
            'username' => 'required|string|max:32|unique:users,username',
            'email' => 'required|email|max:64|unique:users,email',
            'password' => 'required|min:8|max:64|confirmed',
        ]);

        $user = User::create([
            'role_id' => 2,
            'username' => $validated['username'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'is_password_set' => true,
            'status' => 'active',
        ]);

        $session = $this->issueToken($user, $request);
        return response()->json(['message' => 'Registered successfully', 'user' => $session['user'], 'token' => $session['token']], 201);
    }

    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email|max:64',
            'password' => 'required|min:6|max:64',
        ]);

        $user = User::where('email', strtolower($validated['email']))->first();
        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        if ($user->status !== 'active') return response()->json(['message' => 'Account is ' . $user->status], 403);

        $session = $this->issueToken($user, $request);
        return response()->json(['message' => 'Login successful', 'user' => $session['user'], 'token' => $session['token']]);
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
        $user = User::where('email', strtolower($request->email))->first();
        if (!$user) return response()->json(['message' => 'User not found.'], 404);
        return $this->sendOtpTo($request->email, 'Code sent.');
    }

    public function verifyCode(Request $request)
    {
        if (!$this->validOtp($request->email, $request->code)) return response()->json(['message' => 'Invalid code.'], 400);
        return response()->json(['message' => 'Verified.']);
    }

    public function resetPassword(Request $request)
    {
        $user = User::where('email', strtolower($request->email))->first();
        if (!$user || !$this->validOtp($request->email, $request->code)) return response()->json(['message' => 'Invalid request.'], 400);

        $user->password = Hash::make($request->password);
        $user->is_password_set = true;
        $user->save();
        Otp::where('email', strtolower($request->email))->delete();

        return response()->json(['message' => 'Password reset.']);
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
            if ($user->profile_image) Storage::disk('supabase_images')->delete($user->profile_image);
            $user->profile_image = $request->file('profile_image')->store('profile_images', 'supabase_images');
        }

        $user->save();
        return response()->json(['message' => 'Updated.', 'user' => $user]);
    }

    public function socialLogin(Request $request)
    {
        $request->validate(['provider' => 'required|in:google,facebook', 'provider_token' => 'required']);
        $profile = $this->verifySocialToken($request->provider, $request->provider_token);

        if (!$profile) return response()->json(['message' => 'Verification failed.'], 401);

        $email = strtolower($profile['email']);
        $column = $request->provider === 'google' ? 'google_id' : 'facebook_id';

        $user = User::where($column, $profile['id'])->orWhere('email', $email)->first();

        if ($user) {
            if ($user->status !== 'active') return response()->json(['message' => 'Forbidden'], 403);
            $user->$column = $profile['id'];
            $user->save();
        } else {
            $user = User::create([
                'role_id' => 2,
                'username' => $this->generateUniqueUsername($profile['name'] ?? explode('@', $email)[0]),
                'email' => $email,
                'password' => Hash::make(random_bytes(16)),
                'is_password_set' => false,
                $column => $profile['id'],
                'status' => 'active',
            ]);
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
                // Safeguard against missing columns if migration not run
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
            return response()->json(['message' => 'Failed to load security data: ' . $e->getMessage()], 500);
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

        $authOk = ($validated['current_password'] && Hash::check($validated['current_password'], $user->password))
                  || ($validated['code'] && $this->validOtp($user->email, $validated['code']));

        if (!$authOk) return response()->json(['message' => 'Invalid authentication.'], 422);

        $user->password = Hash::make($validated['password']);
        $user->is_password_set = true;
        $user->save();

        if ($validated['code']) Otp::where('email', strtolower($user->email))->delete();

        return response()->json(['message' => 'Password changed.']);
    }

    public function connectSocialAccount(Request $request)
    {
        $user = $request->user();
        $request->validate(['provider' => 'required|in:google,facebook', 'provider_token' => 'required']);

        $profile = $this->verifySocialToken($request->provider, $request->provider_token);
        if (!$profile) return response()->json(['message' => 'Verification failed.'], 401);

        $column = $request->provider === 'google' ? 'google_id' : 'facebook_id';
        if (User::where($column, $profile['id'])->where('id', '!=', $user->id)->exists()) {
            return response()->json(['message' => 'Already connected to another account.'], 409);
        }

        $user->$column = $profile['id'];
        $user->save();

        return response()->json(['message' => 'Connected.', 'user' => $user]);
    }

    public function disconnectSocialAccount(Request $request)
    {
        $user = $request->user();
        $request->validate(['provider' => 'required|in:google,facebook']);

        $column = $request->provider === 'google' ? 'google_id' : 'facebook_id';
        $user->$column = null;
        $user->save();

        return response()->json(['message' => 'Disconnected.', 'user' => $user]);
    }
}
