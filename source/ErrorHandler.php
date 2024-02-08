<?php

class ErrorHandler
{
    /**
     * Handles the given exception and returns a JSON response with the exception details.
     *
     * @param Throwable $exception The exception to be handled.
     * @throws -
     * @return void
     */
    public static function handleException(Throwable $exception): void
    {
        http_response_code(500);

        echo json_encode([
            "code" => $exception->getCode(),
            "message" => $exception->getMessage(),
            "file" => $exception->getFile(),
            "line" => $exception->getLine()
        ]);
    }

    /**
     * Handle an error and throw an ErrorException.
     *
     * @param int $errno The error number.
     * @param string $errstr The error message.
     * @param string $errfile The file where the error occurred.
     * @param int $errline The line number where the error occurred.
     * @throws ErrorException Thrown when an error occurs.
     * @return bool Always returns false.
     */
    public static function handleError(
        int $errno,
        string $errstr,
        string $errfile,
        int $errline
    ): bool {
        throw new ErrorException($errstr, $errno, 0, $errfile, $errline);
    }
}
