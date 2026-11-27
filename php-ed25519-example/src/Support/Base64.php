<?php

declare(strict_types=1);

namespace App\Support;

final class Base64
{
    public static function decodeCanonical(string $value): ?string
    {
        if (strlen($value) % 4 !== 0 || preg_match('/^[A-Za-z0-9+\/]*={0,2}$/D', $value) !== 1) {
            return null;
        }

        $bytes = base64_decode($value, true);

        return $bytes === false ? null : $bytes;
    }
}
