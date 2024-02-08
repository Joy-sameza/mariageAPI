<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require_once "./config/config.php";


class Auth
{
    private JWT $jwt;
    private Key $decodeKey;
    private const KEY = JWT_KEY;
    private const expire = 3600 * HOURS_FOR_EXPIRATION; // token expires after 48 hours

    /**
     * A constructor for the class.
     *
     * @param JWT $jsonWebToken The JSON web token object.
     */
    public function __construct(JWT $jsonWebToken, Key $key)
    {
        $this->jwt = $jsonWebToken;
        $this->decodeKey = $key;
    }

    /**
     * Encodes an array payload into a JWT token string.
     *
     * @param array $payload The array payload to be encoded.
     * @return string The encoded JWT token string.
     */
    public function encode(array $payload): string
    {
        $payload['iat'] = time();
        $payload['exp'] = time() + self::expire;
        return $this->jwt->encode($payload, self::KEY, "HS512");
    }

    /**
     * Verifies a token.
     *
     * @param string $token The token to be verified.
     * @throws Exception If an error occurs during token decoding.
     * @return bool Returns true if the token is valid and has not expired, false otherwise.
     */
    public function verify(string $token): array | false
    {
        try {
            $decodedToken = self::decode($token);
            if (time() > $decodedToken['exp']) return false;
            return [
                'isAdmin' => $decodedToken['isAdmin'],
                'username' => $decodedToken['username'],
            ];
        } catch (Exception) {
            return false;
        }
    }

    /**
     * Decode a token.
     *
     * @param string $token The token to decode.
     * @return array The decoded token as an array.
     * @throws Exception
     */
    public function decode(string $token): array
    {
        return (array)$this->jwt->decode($token, $this->decodeKey);
    }
}
