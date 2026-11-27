<?php

declare(strict_types=1);

namespace App\Config;

use RuntimeException;

final class InvalidConfigurationException extends RuntimeException
{
    public function __construct(public readonly array $errors)
    {
        parent::__construct("Invalid configuration:\n" . implode("\n", array_map(static fn (string $error): string => "  - {$error}", $errors)));
    }
}
