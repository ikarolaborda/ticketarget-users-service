<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

final class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => [
                'required',
                'string',
                'max:120',
            ],
            'email' => [
                'required',
                'email:rfc',
                'max:254',
            ],
            'password' => [
                'required',
                'string',
                Password::min(8),
            ],
        ];
    }

    public function normalizedEmail(): string
    {
        return mb_strtolower(trim($this->validated('email')));
    }
}
