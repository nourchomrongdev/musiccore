<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Otp extends Model
{
    protected $fillable = [
        'email',
        'otp',
        'expires_at'
    ];

    protected $casts = [
        'expires_at' => 'datetime',
    ];

    /**
     * Ensure the email is stored in lowercase.
     */
    public function setEmailAttribute($value)
    {
        $this->attributes['email'] = $value !== null ? strtolower($value) : null;
    }
}
