<?php

namespace App\Services;

use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class FirebaseAuthService
{
    public function verifyIdToken(string $idToken): ?array
    {
        try {
            $parts = explode('.', $idToken);
            if (count($parts) !== 3) {
                return null;
            }

            [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
            $header = json_decode($this->base64UrlDecode($encodedHeader), true);
            $payload = json_decode($this->base64UrlDecode($encodedPayload), true);

            if (!is_array($header) || !is_array($payload) || empty($header['kid'])) {
                return null;
            }

            $projectId = config('services.firebase.project_id');
            if (!$projectId) {
                Log::error('Firebase project id is not configured.');
                return null;
            }

            $issuer = "https://securetoken.google.com/{$projectId}";
            if (($payload['aud'] ?? null) !== $projectId || ($payload['iss'] ?? null) !== $issuer) {
                return null;
            }

            $now = time();
            if (($payload['exp'] ?? 0) < $now || ($payload['iat'] ?? $now + 1) > $now) {
                return null;
            }

            $certs = $this->firebaseCerts();
            $certificate = $certs[$header['kid']] ?? null;
            if (!$certificate) {
                return null;
            }

            $signedData = $encodedHeader . '.' . $encodedPayload;
            $signature = $this->base64UrlDecode($encodedSignature);
            $verified = openssl_verify($signedData, $signature, $certificate, OPENSSL_ALGO_SHA256);

            return $verified === 1 ? $payload : null;
        } catch (Exception $e) {
            Log::error('Firebase token verification failed: ' . $e->getMessage());
            return null;
        }
    }

    public function updatePassword(string $firebaseUid, string $password): bool
    {
        try {
            $projectId = config('services.firebase.project_id');
            $accessToken = $this->accessToken();

            if (!$projectId || !$accessToken) {
                return false;
            }

            $response = Http::withToken($accessToken)->post(
                "https://identitytoolkit.googleapis.com/v1/projects/{$projectId}/accounts:update",
                [
                    'localId' => $firebaseUid,
                    'password' => $password,
                ]
            );

            if ($response->successful()) {
                return true;
            }

            Log::error('Firebase password update failed: ' . $response->body());
            return false;
        } catch (Exception $e) {
            Log::error('Firebase password update exception: ' . $e->getMessage());
            return false;
        }
    }

    public function syncEmailPasswordUser(string $email, string $password): ?string
    {
        try {
            $apiKey = config('services.firebase.api_key');
            if (!$apiKey) {
                Log::error('Firebase API key is not configured.');
                return null;
            }

            $response = Http::post(
                "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={$apiKey}",
                [
                    'email' => strtolower(trim($email)),
                    'password' => $password,
                    'returnSecureToken' => false,
                ]
            );

            if ($response->successful()) {
                return $response->json('localId');
            }

            $errorMessage = $response->json('error.message');
            if ($errorMessage === 'EMAIL_EXISTS') {
                return $this->signInEmailPasswordUser($email, $password);
            }

            Log::error('Firebase email/password sync failed: ' . $response->body());
            return null;
        } catch (Exception $e) {
            Log::error('Firebase email/password sync exception: ' . $e->getMessage());
            return null;
        }
    }

    private function signInEmailPasswordUser(string $email, string $password): ?string
    {
        $apiKey = config('services.firebase.api_key');
        if (!$apiKey) {
            return null;
        }

        $response = Http::post(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={$apiKey}",
            [
                'email' => strtolower(trim($email)),
                'password' => $password,
                'returnSecureToken' => false,
            ]
        );

        if ($response->successful()) {
            return $response->json('localId');
        }

        Log::error('Firebase email/password sign-in failed during sync: ' . $response->body());
        return null;
    }

    private function firebaseCerts(): array
    {
        return Cache::remember('firebase_securetoken_certs', now()->addHours(6), function () {
            $response = Http::get('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
            return $response->successful() ? $response->json() : [];
        });
    }

    private function accessToken(): ?string
    {
        return Cache::remember('firebase_admin_access_token', now()->addMinutes(50), function () {
            $credentials = $this->serviceAccountCredentials();
            if (!$credentials) {
                Log::error('Firebase service account credentials are not configured.');
                return null;
            }

            $now = time();
            $jwtHeader = ['alg' => 'RS256', 'typ' => 'JWT'];
            $jwtPayload = [
                'iss' => $credentials['client_email'],
                'scope' => 'https://www.googleapis.com/auth/identitytoolkit',
                'aud' => 'https://oauth2.googleapis.com/token',
                'iat' => $now,
                'exp' => $now + 3600,
            ];

            $unsignedJwt = $this->base64UrlEncode(json_encode($jwtHeader)) . '.' .
                $this->base64UrlEncode(json_encode($jwtPayload));

            $signature = '';
            openssl_sign($unsignedJwt, $signature, $credentials['private_key'], OPENSSL_ALGO_SHA256);
            $assertion = $unsignedJwt . '.' . $this->base64UrlEncode($signature);

            $response = Http::asForm()->post('https://oauth2.googleapis.com/token', [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $assertion,
            ]);

            if (!$response->successful()) {
                Log::error('Firebase OAuth token request failed: ' . $response->body());
                return null;
            }

            return $response->json('access_token');
        });
    }

    private function serviceAccountCredentials(): ?array
    {
        $json = config('services.firebase.credentials_json');
        $path = config('services.firebase.credentials');

        if ($json) {
            $credentials = json_decode($json, true);
        } elseif ($path && is_file($path)) {
            $credentials = json_decode(file_get_contents($path), true);
        } else {
            $credentials = [
                'client_email' => config('services.firebase.client_email'),
                'private_key' => config('services.firebase.private_key'),
            ];
        }

        if (empty($credentials['client_email']) || empty($credentials['private_key'])) {
            return null;
        }

        $credentials['private_key'] = str_replace('\\n', "\n", $credentials['private_key']);
        return $credentials;
    }

    private function base64UrlDecode(string $value): string
    {
        $base64 = strtr($value, '-_', '+/');
        $padding = strlen($base64) % 4;
        if ($padding) {
            $base64 .= str_repeat('=', 4 - $padding);
        }

        return base64_decode($base64);
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
