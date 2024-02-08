<?php
class Controller
{
    /**
     * Constructs a new instance of the class.
     *
     * @param RegisterLogin $RegisterLogin The RegisterLoginrier object.
     */
    public function __construct(private Authenticate $RegisterLogin)
    {
    }

    /**
     * Process a request.
     *
     * @param string $method The HTTP method of the request.
     * @param string $path The path of the resource to process.
     * @throws Some_Exception_Class A description of the exception.
     * @return void
     */
    public function processRequest(string $method, string $path, ?string $id): void
    {
        if (!empty($id) && (str_contains($path, "update") || $path === "delete" || $path === "qrencode")) $this->getResourceRequest($method, $id, $path);
        else $this->getResourceCollection($method, $path);
    }

    /**
     * Handles the resource collection based on the given method and path.
     *
     * @param string $path The resource path.
     * @return void
     */
    private function getResourceCollection(string $method, string $path): void
    {
        switch ($method) {
            case 'GET':
                if (str_contains($path, "userList")) {
                    $path = "userList";
                }
                if (str_contains($path, "guestList")) {
                    $path = "guestList";
                }
                switch ($path) {
                    case 'isVerified':
                        //get token from user
                        $authorization = $this->retrieveAuthorizationFromHeaders();
                        if ($authorization === null) {
                            http_response_code(401);
                            echo json_encode([
                                "error" => "Unauthorized",
                            ]);
                            return;
                        }
                        $token = explode(" ", $authorization)[1];
                        $err = $this->getValidationErrors(["token" => $token], 'isVerified');
                        if (!empty($err)) {
                            http_response_code(400);
                            echo json_encode(['errors' => $err]);
                            return;
                        }
                        $output = $this->RegisterLogin->verified($token);
                        if (!$output) {
                            http_response_code(401);
                            echo json_encode([
                                "error" => "Unauthorized or invalid token",
                            ]);
                            return;
                        }
                        echo json_encode($output);
                        break;
                    case 'userList':
                        if (!isset($_REQUEST['admin'])) {
                            http_response_code(401);
                            echo json_encode([
                                "error" => "Unauthorized",
                            ]);
                            return;
                        }
                        $admin = filter_var($_REQUEST['admin'], FILTER_SANITIZE_NUMBER_INT);
                        $page = isset($_REQUEST['page']) && is_int((int)$_REQUEST['page']) ? (int)$_REQUEST['page'] : 1;
                        $limit = isset($_REQUEST['per_page']) && is_int((int)$_REQUEST['per_page']) ? (int)$_REQUEST['per_page'] : 20;

                        $output = $this->RegisterLogin->userList($admin, $page, $limit);
                        if ($output === false) {
                            http_response_code(404);
                            echo json_encode([
                                "error" => "Admin reference in user list not found",
                            ]);
                            return;
                        }
                        echo json_encode($output);
                        break;
                    case 'guestList':
                        if (!isset($_REQUEST['admin'])) {
                            http_response_code(401);
                            echo json_encode([
                                "error" => "Unauthorized",
                            ]);
                            return;
                        }
                        $admin = filter_var($_REQUEST['admin'], FILTER_SANITIZE_NUMBER_INT);
                        $page = isset($_REQUEST['page']) && is_int((int)$_REQUEST['page']) ? (int)$_REQUEST['page'] : 1;
                        $limit = isset($_REQUEST['per_page']) && is_int((int)$_REQUEST['per_page']) ? (int)$_REQUEST['per_page'] : 20;

                        $output = $this->RegisterLogin->guestList($admin, $page, $limit);
                        if ($output === false) {
                            http_response_code(404);
                            echo json_encode([
                                "error" => "Admin reference in guest list not found",
                            ]);
                            return;
                        }
                        echo json_encode($output);
                        break;
                    default:
                        http_response_code(404);
                        echo json_encode(["error" => "Path not found"]);
                        break;
                }
                break;
            case 'POST':
                switch ($path) {
                    case 'login':
                        $data = $this->getUserInputsAndVerify($path);
                        if (empty($data)) return;
                        $output = $this->RegisterLogin->login($data);
                        if ($output === false) {
                            http_response_code(401);
                            echo json_encode([
                                "error" => "Invalid credentials",
                            ]);
                            return;
                        }
                        http_response_code(200);
                        echo json_encode($output);
                        break;
                    case 'register':
                        $data = $this->getUserInputsAndVerify($path);
                        if (empty($data)) return;
                        $output = $this->RegisterLogin->register($data);
                        if ($output === false) {
                            http_response_code(409);
                            echo json_encode([
                                "error" => "User already exists",
                            ]);
                            return;
                        }
                        if (is_array($output) && array_key_exists("ad_error", $output)) {
                            http_response_code(404);
                            echo json_encode([
                                "error" => "Admin with given id not found",
                            ]);
                            return;
                        }
                        http_response_code(201);
                        echo json_encode([
                            "message" => "Registered successfully",
                            "info" => $output,
                        ]);
                        break;
                    case 'registerGuest':
                        $data = $this->getUserInputsAndVerify($path);
                        if (empty($data)) return;
                        $output = $this->RegisterLogin->addGuest($data);
                        if ($output === false) {
                            http_response_code(409);
                            echo json_encode([
                                "error" => "Guest already exists",
                            ]);
                            return;
                        }
                        if (is_array($output) && array_key_exists("ad_error", $output)) {
                            http_response_code(404);
                            echo json_encode([
                                "error" => "Admin with given id not found",
                            ]);
                            return;
                        }
                        http_response_code(201);
                        echo json_encode([
                            "message" => "Registered guest successfully"
                        ]);
                        break;
                    case 'registerAdmin':
                        $data = $this->getUserInputsAndVerify($path);
                        if (empty($data)) return;
                        $output = $this->RegisterLogin->registerAdmin($data);
                        if ($output === false) {
                            http_response_code(409);
                            echo json_encode([
                                "error" => "Admin already exists",
                            ]);
                            return;
                        }
                        http_response_code(201);
                        echo json_encode([
                            "message" => "Registered successfully",
                            "info" => $output,
                        ]);
                        break;
                    case 'qrdecode':
                        $data = $this->getUserInputsAndVerify($path);
                        if (empty($data)) return;
                        $out = $this->RegisterLogin->decodeForQRCode($data['data']);
                        if ($out === false) {
                            http_response_code(400);
                            echo json_encode(['error' => "Invalid QR Code", 'data' => $data]);
                            break;
                        }
                        echo json_encode(['qrdata' => $out]);
                        break;
                    default:
                        http_response_code(404);
                        echo json_encode(["error" => "Path not found"]);
                        break;
                }
                break;
            default:
                http_response_code(405);
                echo json_encode([
                    "error" => "Method is not allowed",
                ]);
                break;
        }
    }

    /**
     * Retrieves a resource request based on the provided method, id, and path.
     *
     * @param string $method The HTTP method used for the request.
     * @param string $id The ID of the resource.
     * @param string $path The path of the resource.
     * @return void
     */
    private function getResourceRequest(string $method, string $id, string $path): void
    {
        $err = null;
        if (!isset($id)) {
            $err = ['id' => 'ID is requiredin the URI'];
        }
        if (!is_int((int)$id)) {
            $err = ['id' => 'ID must be an integer'];
        }
        if ($err) {
            http_response_code(400);
            echo json_encode(['error' => $err]);
            return;
        }
        $data = $this->RegisterLogin->get($id, $path === "update" || $path === "delete");
        if (!$data) {
            http_response_code(404);
            echo json_encode([
                'error' => ($path !== "update" && $path !== "delete") ? 'Guest not found' : 'User not found'
            ]);
            return;
        }
        switch ($method) {
            case 'GET':
                $out = $this->RegisterLogin->encodeForQRCode($id);
                if (!$out) {
                    http_response_code(404);
                    echo json_encode(["error" => "Guest not found"]);
                    return;
                }
                echo json_encode(["qrdata" => $out]);
                break;
            case 'PATCH':
                if ($path === "update") {
                    $newData = $this->getUserInputsAndVerify('update');
                    $res = $this->RegisterLogin->updateUser($newData, $data);
                    if (!$res) {
                        http_response_code(304);
                        echo json_encode(["message" => "Nothing to modify"]);
                        break;
                    }
                    echo json_encode([
                        "message" => "Updated successfully",
                        "user" => "$data[name]",
                    ]);
                    break;
                }
                if ($path === 'updateGuest') {
                    $data = $this->RegisterLogin->get($id, false);
                    $newData = $this->getUserInputsAndVerify('update');
                    $res = $this->RegisterLogin->updateGuest($id, $data['admin_ref'], $newData);
                    if (!$res) {
                        http_response_code(304);
                        echo json_encode(["message" => "Nothing to modify"]);
                        break;
                    }
                    $name = $newData['actual_name'] ?? $data['actual_name'];
                    echo json_encode([
                        "message" => "Updated successfully",
                        "guest" => "$name",
                    ]);
                    break;
                }
                break;
            case 'DELETE':
                if ($path !== "delete") {
                    http_response_code(400);
                    echo json_encode(["error" => "Invalid request"]);
                    break;
                }
                $newData = $this->getUserInputsAndVerify('delete');
                if ($data['admin_ref'] !== $newData['admin_ref']) {
                    http_response_code(401);
                    echo json_encode([
                        'error' => 'You do not have permission to delete this user'
                    ]);
                    break;
                }
                $res = $this->RegisterLogin->deleteUser($id, $newData['admin_ref']);
                if ($res === false) {
                    http_response_code(500);
                    echo json_encode([
                        'error' => 'An error occured'
                    ]);
                    break;
                }
                echo json_encode([
                    "message" => "Deleted successfully",
                    "user" => "$data[name]",
                ]);
                break;
            default:
                http_response_code(405);
                echo json_encode([
                    "error" => "Method is not allowed for this resource",
                ]);
                break;
        }
    }

    /**
     * Retrieves validation errors from the given data array.
     *
     * @param array $data The data array to validate.
     * @param bool $isNew Whether the data is for a new entry.
     * @return array The array of validation errors.
     */
    private function getValidationErrors(array $data, string $path, bool $isNew = false): array
    {

        static $password_regex = '/^.{6,}$/';
        static $telephone_regex = '/^((\+|00)?237)?([62](2|3|[5-9])[0-9]{7})$/';

        $errors = [];

        if (empty($data['username']) && $path === "login") {
            $errors['username'] = "User name is required";
        }

        if (($path === "registerAdmin" || $path === "login") && empty($data['password'])) {
            $errors['password'] = "Password is required";
        }
        if ($isNew) {
            if (empty($data['telephone'])) {
                $errors['telephone'] = "Telephone is required";
            } elseif (!preg_match($telephone_regex, $data['telephone'])) {
                $errors['telephone'] = "Invalid telephone number";
            }

            if (!empty($data['password']) && !preg_match($password_regex, $data['password'])) {
                $errors['password'] = "Password must be at least 6 characters";
            }
            if (empty($data['actual_name']) || (!empty($data['actual_name']) && trim($data['actual_name']) === "")) {
                $errors['actual_name'] = "Actual name is required";
            }
            if ($path === "register" && empty($data['admin_id'])) {
                $errors['admin_id'] = "Admin Reference ID is required";
            }
        }
        if ($path === 'isVerified' && empty($data['token'])) {
            $errors['token'] = "Authorization token is required";
        }
        if ($path === 'delete') {
            $id = $data['id'] ?? null;
            $admin_ref = $data['admin_ref'] ?? null;

            if (empty($id)) {
                $errors['id'] = "Id in URI is required";
            } elseif (!is_numeric($id) || !is_int((int) $id)) {
                $errors['id'] = "Id in URI should be an integer";
            }
            if (!isset($admin_ref)) {
                $errors['admin_ref'] = "Admin Reference in URI is required";
            } elseif (!is_numeric($admin_ref) || !is_int((int) $admin_ref)) {
                $errors['admin_ref'] = "Admin Reference in URI should be an integer";
            }
        }
        if ($path === 'update') {
        }
        if ($path === 'qrdecode' && empty($data['data'])) {
            $errors['data'] = "Data to be decoded is required";
        }
        return $errors;
    }

    /**
     * Retrieves user inputs from the request body and verifies their validity.
     *
     * @param string $path The path of the request.
     * @return array The validated user inputs.
     */
    private function getUserInputsAndVerify(string $path): array
    {
        $data = (array)json_decode(file_get_contents("php://input"), true);
        if (empty($data)) {
            http_response_code(400);
            echo json_encode([
                "error" => "Invalid data",
            ]);
            return [];
        }
        $errors = $this->getValidationErrors($data, $path, $path === "register" || $path === "registerAdmin");
        if (!empty($errors)) {
            http_response_code(400);
            echo json_encode([
                "errors" => $errors,
            ]);
            return [];
        }
        return $data;
    }

    /**
     * Retrieves the authorization from the request headers.
     *
     * @return string|null The authorization token or null if not found.
     */
    private function retrieveAuthorizationFromHeaders(): ?string
    {
        $headers = getallheaders();
        if (isset($headers['Authorization'])) {
            return $headers['Authorization'];
        }
        if (isset($headers['authorization'])) {
            return $headers['authorization'];
        }
        return null;
    }
}
