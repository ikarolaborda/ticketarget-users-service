<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class UpdateProfileRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => [
                'sometimes',
                'string',
                'max:120',
            ],
            'email' => [
                'sometimes',
                'email:rfc',
                'max:254',
            ],
        ];
    }

    public function normalizedEmail(): ?string
    {
        $email = $this->validated('email');

        return $email === null ? null : mb_strtolower(trim($email));
    }
}
