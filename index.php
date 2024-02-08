<?php

declare(strict_types=1);

// Auto load classes
spl_autoload_register(function ($class) {
    require __DIR__ . "/source/$class.php";
});
require_once __DIR__ . '/config/config.php';
require_once "./vendor/autoload.php";

use Firebase\JWT\Key;
use Firebase\JWT\JWT;

header('Access-Control-Allow-Origin: *');
header("Content-Type: application/json; charset=UTF-8");

// Handle errors and exceptions
set_error_handler("ErrorHandler::handleError");
set_exception_handler("ErrorHandler::handleException");

$request = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

$part = explode("/", $request);
if ($part[1] != 'auth')
    return http_response_code(404);

$path = $part[2];
$id = null;
if (!empty($part[3])) $id = $part[3];

ini_set("date.timezone", "Africa/Douala");

$database = new Database(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);

$key = new Key(JWT_KEY, 'HS512');
$auth = new Auth(new JWT(), $key);

$authenticate = new Authenticate($database, $auth);

$controller = new Controller($authenticate);

$controller->processRequest($method, $path, $id);
