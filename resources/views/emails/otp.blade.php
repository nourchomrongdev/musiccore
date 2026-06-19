<!DOCTYPE html>
<html>
<head>
    <style>
        .container { font-family: sans-serif; padding: 20px; color: #333; }
        .code { font-size: 32px; font-weight: bold; color: #2336B8; letter-spacing: 5px; padding: 10px; background: #f4f4f4; border-radius: 8px; display: inline-block; }
        .footer { margin-top: 20px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Security Verification Code</h2>
        <p>Hello,</p>
        <p>Your verification code for <strong>MusicStream</strong> is:</p>
        <div class="code">{{ $otp }}</div>
        <p>This code will expire in 15 minutes.</p>
        <p>If you did not request this code, please ignore this email.</p>
        <div class="footer">
            &copy; {{ date('Y') }} MusicStream. All rights reserved.
        </div>
    </div>
</body>
</html>
