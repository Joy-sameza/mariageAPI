<?php

class Authenticate
{
    /**
     * @var PDO|null $connection The database connection.
     */
    private ?PDO $connection;
    /**
     * @var Auth $authTokens
     * This variable holds the Auth object for managing authentication tokens.
     */
    private Auth $authTokens;
    private string $tableName = STAFF_TABLE, $adminTableName = ADMIN_TABLE, $guestTable = GUEST_TABLE;

    /**
     * Constructor for the class.
     *
     * @param Database $database The database connection object.
     * @param Auth $auth The authentication object.
     */
    public function __construct(Database $database, Auth $auth)
    {
        $this->connection = $database->connect();
        $this->authTokens = $auth;
    }


    /**
     * @OA\Get(
     *   path="/update",
     *   summary="Get user details for update",
     *   description="Retrieves user details for update based on admin authorization.",
     *   @OA\Parameter(
     *     name="id",
     *     in="query",
     *     required=true,
     *     description="User ID",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="User details for update",
     *     @OA\JsonContent(ref="#/components/schemas/UserInfo"),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     *   @OA\Response(
     *     response=404,
     *     description="User not found",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="User not found"),
     *     ),
     *   ),
     * )
     */
    /**
     * Retrieves a user| guest from the database based on the provided ID.
     *
     * @param string $id The ID of the user to retrieve.
     * @param boolean $isStaff Whether to return staff users or not.
     * @return array|false The retrieved user as an array or false if no user is found.
     */
    public function get(string $id, bool $isStaff): array | false
    {
        $sql = "SELECT * FROM {$this->guestTable} WHERE archived = 0 AND id = :id";
        if ($isStaff) {
            $sql = "SELECT * FROM {$this->tableName} WHERE archived = 0 AND id = :id";
        }
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':id', $id);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    /**
     * Logs in a user with the provided username and password.
     *
     * @param array $data An associative array containing the username and password.
     * @return array|false Returns an associative array with the username, response, and token on success. Returns false on failure.
     */
    public function login(array $data): array | false
    {
        $username = $data['username'];
        $password = $data['password'];

        // Sanitize the username and password
        $username = htmlspecialchars(strip_tags($username));
        $password = htmlspecialchars(strip_tags($password));

        //
        $sql_user = "SELECT password FROM {$this->tableName} WHERE name = :username AND archived = 0";
        $stmt_user = $this->connection->prepare($sql_user);
        $stmt_user->bindParam(':username', $username);
        $stmt_user->execute();

        $hashed = $stmt_user->fetch(PDO::FETCH_ASSOC);

        //
        if (!$hashed) {
            $sql_admin = "SELECT id, password FROM {$this->adminTableName} WHERE name = :username AND archived = 0";
            $stmt_admin = $this->connection->prepare($sql_admin);
            $stmt_admin->bindParam(':username', $username);
            $stmt_admin->execute();
            $hashed = $stmt_admin->fetch(PDO::FETCH_ASSOC);
            if ($hashed) $hashed['admin'] = true;
        }
        if (!$hashed) return false;

        if (password_verify($password, $hashed['password'])) {
            $token = $this->authTokens->encode([
                'username' => $username,
                'password' => $hashed['password'],
                "isAdmin" => !empty($hashed['admin']),
            ]);
            $x = [
                'username' => strtoupper($username),
                'response' => true,
                'token' => $token,
                "message" => "Logged in successfully",
                "isAdmin" => !empty($hashed['admin']),
            ];
            if (isset($hashed['id'])) $x['admin_id'] = $hashed['id'];
            return $x;
        }
        return false;
    }

    /**
     * Registers a user with the provided data.
     *
     * @param array $data The data of the user to be registered.
     * @return array|false Returns an array with the registered user's details or false if the user already exists.
     */
    public function register(array $data): array | false
    {
        $actual_name = $data['actual_name'];
        $telephone = $data['telephone'];
        $admin_id = $data['admin_id'];

        // Sanitize the username and password
        $actual_name = htmlspecialchars(strip_tags($actual_name));
        $telephone = htmlspecialchars(strip_tags($telephone));
        $admin_id = htmlspecialchars(strip_tags($admin_id));

        $test_sql = "SELECT * FROM {$this->tableName} WHERE actual_name = :actual_name AND admin_ref = :admin_id";
        $test_stmt = $this->connection->prepare($test_sql);
        $test_stmt->bindParam(':actual_name', $actual_name);
        $test_stmt->bindParam(':admin_id', $admin_id);
        $test_stmt->execute();
        $exist = $test_stmt->fetch(PDO::FETCH_ASSOC);
        if ($exist) return false;

        $admin_name = $this->getAdminName($admin_id);
        if (!$admin_name) return ['ad_error' => true];
        $username = "";
        $namePresent = $this->getLastRowByName($this->tableName, $admin_name, false);
        if ($namePresent) {
            $n = (int)explode('_', $namePresent)[1] + 1;
            $username = $admin_name . "_" . str_pad($n, 3, "0", STR_PAD_LEFT);
        } else $username = $admin_name . "_001";

        $password = password_hash($username, PASSWORD_DEFAULT);

        $sql = "INSERT INTO {$this->tableName} (name, password, telephone, actual_name, admin_ref) VALUES (:username, :password, :telephone, :actual_name, :admin_id)";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':telephone', $telephone);
        $stmt->bindParam(':actual_name', $actual_name);
        $stmt->bindParam(':admin_id', $admin_id);
        if (!$stmt->execute()) return false;
        return [
            'id' => (int)$this->connection->lastInsertId() ?: -1,
            'username' => $username,
            'password' => $username,
        ];
    }

    /**
     * Registers an admin user.
     *
     * @param array $data An array containing the admin user data.
     *                    The array must have the following keys:
     *                    - actual_name: The actual name of the admin user.
     *                    - password: The password of the admin user.
     *                    - telephone: The telephone number of the admin user.
     *
     * @throws PDOException If there is an error executing the SQL statements.
     *
     * @return string|false Returns the ID of the newly registered admin user on success,
     *                     or false if the admin user already exists.
     */
    public function registerAdmin(array $data): array | false
    {
        $actual_name = $data['actual_name'];
        $password = $data['password'];
        $telephone = $data['telephone'];

        // Sanitize the username and password
        $actual_name = htmlspecialchars(strip_tags($actual_name));
        $password = htmlspecialchars(strip_tags($password));
        $telephone = htmlspecialchars(strip_tags($telephone));

        $test_sql = "SELECT * FROM {$this->adminTableName} WHERE actual_name = :actual_name AND archived = 0";
        $test_stmt = $this->connection->prepare($test_sql);
        $test_stmt->bindParam(':actual_name', $actual_name);
        $test_stmt->execute();
        $exist = $test_stmt->fetch(PDO::FETCH_ASSOC);
        if ($exist) return false;

        // Hash the password
        $password = password_hash($password, PASSWORD_DEFAULT);

        $names = explode(" ", $actual_name);
        $username = "";
        if (count($names) === 1) {
            if (strlen($names[0]) < 4) {
                $username = str_pad(strtoupper($names[0]), 4, '$');
            } else $username = strtoupper(substr($actual_name, 0, 4));
        } else {
            foreach ($names as $name) {
                $capped = strtoupper(substr($name, 0, 2));
                $username .= $capped;
                if (strlen($username) >= 4) break;
            }
        }
        $namePresent = $this->getLastRowByName($this->adminTableName, $username, true);
        if ($namePresent !== null) {
            $lastNumbers = (int)substr($namePresent, 4);
            $username .= $lastNumbers + 1;
        }

        $now = date('Y-m-d H:i:s');
        $sql = "INSERT INTO {$this->adminTableName} (name, password, telephone, actual_name, created_at) VALUES (:username, :password, :telephone, :actual_name, :created_at)";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':telephone', $telephone);
        $stmt->bindParam(':actual_name', $actual_name);
        $stmt->bindParam(':created_at', $now);
        if (!$stmt->execute()) return false;
        return [
            'id' => $this->connection->lastInsertId(),
            'username' => $username
        ];
    }

    /**
     * Updates a user in the database.
     *
     * @param array $data The new data for the user.
     * @param array $current The current data of the user.
     * @return bool True if the update was successful, false otherwise.
     */
    public function updateUser(array $data, array $current): ?bool
    {
        $sql = "UPDATE {$this->tableName} 
            SET 
                archived = :archived, 
                password = :password, 
                telephone = :telephone, 
                actual_name = :actual_name 
            WHERE admin_ref = :admin_ref
            ";
        $stmt = $this->connection->prepare($sql);

        if (htmlspecialchars(strip_tags($data['admin_id'])) != $current['admin_ref']) return null;
        $sanitizedData = array_map(function ($item) {
            return htmlspecialchars(strip_tags($item ?? ''));
        }, $data);

        $sanitizedData['archived'] ??= $current['archived'];
        $sanitizedData['password'] ??= $current['password'];
        $sanitizedData['telephone'] ??= $current['telephone'];
        $sanitizedData['actual_name'] ??= $current['actual_name'];

        $stmt->bindParam(':archived', $sanitizedData['archived'], PDO::PARAM_INT);
        $stmt->bindParam(':password', $sanitizedData['password'], PDO::PARAM_STR);
        $stmt->bindParam(':telephone', $sanitizedData['telephone'], PDO::PARAM_STR);
        $stmt->bindParam(':actual_name', $sanitizedData['actual_name'], PDO::PARAM_STR);
        $stmt->bindParam(':admin_ref', $current['admin_ref'], PDO::PARAM_INT);

        $stmt->execute();
        return $stmt->rowCount() > 0;
    }

    /**
     * @OA\Delete(
     *   path="/delete",
     *   summary="Delete user",
     *   description="Deletes a user based on the provided data.",
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/DeleteUserInput"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="User deleted successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="message", type="string", example="Deleted successfully"),
     *       @OA\Property(property="user", type="string", example="John Doe"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     *   @OA\Response(
     *     response=401,
     *     description="Unauthorized",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="You do not have permission to delete this user"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=500,
     *     description="Internal Server Error",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="An error occurred"),
     *     ),
     *   ),
     * )
     */
    /**
     * Deletes a user from the database.
     *
     * @param string $id The ID of the user to be deleted.
     * @throws Some_Exception_Class If there is an error executing the SQL statement.
     * @return bool Returns true if the user is successfully deleted, false otherwise.
     */
    public function deleteUser(string $id, string $admin_ref): bool
    {
        $id = htmlspecialchars(strip_tags($id));
        $admin_ref = htmlspecialchars(strip_tags($admin_ref));
        $sql = "DELETE FROM {$this->tableName} WHERE id = :id AND admin_ref = :admin_ref;";
        $stmt = $this->connection->prepare($sql);
        $new_id = (int)$id;
        $new_admin_ref = (int)$admin_ref;
        $stmt->bindParam(':id', $new_id, PDO::PARAM_INT);
        $stmt->bindParam(':admin_ref', $new_admin_ref, PDO::PARAM_INT);
        return $stmt->execute();
    }

    /**
     * @OA\Get(
     *   path="/verify/token",
     *   summary="Checks the validity of a token.",
     *   @OA\Parameter(
     *     name="token",
     *     in="query",
     *     description="Authentication token to be verified.",
     *     required=true,
     *     @OA\Schema(type="string")
     *   ),
     *   @OA\Response(response=200, description="Token is valid"),
     *   @OA\Response(response=401, description="Token is invalid"),
     * )
     */
    /** 
     * Checks for the calidity of a token and returns true if valid and false otherwise.
     * 
     * @param string $token The authentication token to be verified.
     * @return boolean True if the token is valid and false otherwise.
     */
    public function verified(string $token): array | false
    {
        return $this->authTokens->verify($token);
    }

    /**
     * @OA\Post(
     *   path="/addGuest",
     *   summary="Add a new guest",
     *   description="Adds a new guest with the provided information.",
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/AddGuestInput"),
     *   ),
     *   @OA\Response(
     *     response=201,
     *     description="Guest added successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="message", type="string", example="Guest added successfully"),
     *       @OA\Property(property="guest", ref="#/components/schemas/GuestInfo"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     *   @OA\Response(
     *     response=409,
     *     description="Guest already exists",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Guest already exists"),
     *     ),
     *   ),
     * )
     */
    /**
     * Adds a guest to the database.
     *
     * @param array $data The data of the guest to be added.
     *                    The array should contain the following keys:
     *                    - `actual_name`: The actual name of the guest.
     *                    - `table_number`: The table number of the guest.
     *                    - `admin_id`: The admin reference of the guest.
     *                    - `telephone`: The telephone number of the guest.
     * @return bool Returns true if the guest was successfully added, false otherwise.
     */
    public function addGuest(array $data): array | bool
    {
        $data['actual_name'] = htmlspecialchars(strip_tags($data['actual_name']));
        $data['table_number'] = htmlspecialchars(strip_tags($data['table_number']));
        $data['admin_ref'] = htmlspecialchars(strip_tags($data['admin_id']));
        $data['telephone'] = htmlspecialchars(strip_tags($data['telephone']));

        $sql = "INSERT INTO 
                    {$this->guestTable} 
                        (`actual_name`, `table_number`, `admin_ref`, `telephone`) 
                    VALUES 
                        (:actual_name, :table_number, :admin_ref, :telephone)
                ";

        $adminName = $this->getAdminName((int)$data['admin_ref']);
        if (!$adminName) return ["ad_error" => true];
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':actual_name', $data['actual_name']);
        $stmt->bindParam(':table_number', $data['table_number']);
        $stmt->bindParam(':admin_ref', $data['admin_ref']);
        $stmt->bindParam(':telephone', $data['telephone']);
        return $stmt->execute();
    }

    /**
     * @OA\Delete(
     *   path="/deleteGuest",
     *   summary="Delete guest",
     *   description="Deletes a guest based on the provided data.",
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/DeleteGuestInput"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="Guest deleted successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="message", type="string", example="Guest deleted successfully"),
     *       @OA\Property(property="guest", ref="#/components/schemas/GuestInfo"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     *   @OA\Response(
     *     response=401,
     *     description="Unauthorized",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="You do not have permission to delete this guest"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=500,
     *     description="Internal Server Error",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="An error occurred"),
     *     ),
     *   ),
     * )
     */
    /**
     * Deletes a guest with the specified ID and admin reference from the guest table.
     *
     * @param string $id The ID of the guest to delete.
     * @param string $admin_ref The admin reference of the guest to delete.
     * @return bool Returns true if the guest was successfully deleted, false otherwise.
     */
    public function deleteGuest(string $id, string $admin_ref): bool
    {
        $id = htmlspecialchars(strip_tags($id));
        $admin_ref = htmlspecialchars(strip_tags($admin_ref));
        $sql = "DELETE FROM {$this->guestTable} WHERE id = :id AND admin_ref = :admin_ref";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':admin_ref', $admin_ref);
        return $stmt->execute();
    }

    /**
     * @OA\Patch(
     *   path="/updateGuest",
     *   summary="Update guest details",
     *   description="Updates guest details based on the provided data.",
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/UpdateGuestInput"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="Guest details updated successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="message", type="string", example="Updated successfully"),
     *       @OA\Property(property="guest", type="string", example="Jane Doe"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=304,
     *     description="No modification needed",
     *     @OA\JsonContent(
     *       @OA\Property(property="message", type="string", example="Nothing to modify"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     * )
     */
    /**
     * Updates a guest in the database.
     *
     * @param string $id The ID of the guest to update.
     * @param string $admin_ref The admin reference of the guest to update.
     * @param array $newData The new data to update the guest with.
     * @return bool Returns true if the guest was successfully updated, false otherwise.
     */
    public function updateGuest(string $id, string $admin_ref, array $newData): bool
    {
        $newData['actual_name'] = ($newData['actual_name']) ? htmlspecialchars(strip_tags($newData['actual_name'])) : null;
        $newData['table_number'] = ($newData['table_number']) ? htmlspecialchars(strip_tags($newData['table_number'])) : null;
        $newData['admin_ref'] = ($newData['admin_ref']) ? htmlspecialchars(strip_tags($newData['admin_ref'])) : null;
        $newData['telephone'] = ($newData['telephone']) ? htmlspecialchars(strip_tags($newData['telephone'])) : null;

        $sql = "UPDATE {$this->guestTable} SET";
        $params = [];

        if ($newData['actual_name']) {
            $sql .= " actual_name = :actual_name,";
            $params[':actual_name'] = $newData['actual_name'];
        }
        if ($newData['table_number']) {
            $sql .= " table_number = :table_number,";
            $params[':table_number'] = $newData['table_number'];
        }
        if ($newData['admin_ref']) {
            $sql .= " admin_ref = :admin_ref,";
            $params[':admin_ref'] = $newData['admin_ref'];
        }
        if ($newData['telephone']) {
            $sql .= " telephone = :telephone,";
            $params[':telephone'] = $newData['telephone'];
        }

        // Remove the trailing comma from the SQL statement
        $sql = rtrim($sql, ',');

        $sql .= " WHERE id = :id AND admin_ref = :admin_ref AND archived = 0";
        $params[':id'] = $id;
        $params[':admin_ref'] = $admin_ref;

        $stmt = $this->connection->prepare($sql);
        $stmt->execute($params);

        return $stmt->rowCount() > 0;
    }

    /**
     * @OA\Get(
     *   path="/qrencode",
     *   summary="Encode user for QR Code",
     *   description="Encodes user information for a QR Code based on the provided ID.",
     *   @OA\Parameter(
     *     name="id",
     *     in="query",
     *     required=true,
     *     description="User ID",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="User encoded for QR Code successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="qrdata", type="string"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=404,
     *     description="User not found",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="User not found"),
     *     ),
     *   ),
     * )
     */
    /**
     * Search for the guest in the database and return the guest as encoded string.
     * 
     * @param string $guest_id The guest identifier to be searched.
     * @return string|false The guest as encoded string or false if not found.
     */
    public function encodeForQRCode(string $guest_id): string | false
    {
        $guest = self::get($guest_id, false);
        if (!$guest) return false;
        $hashed1 = $this->authTokens->encode($guest);
        $r = base64_encode($hashed1);
        return base64_encode($hashed1);
    }


    /**
     * @OA\Post(
     *   path="/qrdecode",
     *   summary="Decode QR Code",
     *   description="Decodes the provided data as a QR Code.",
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(ref="#/components/schemas/QRDecodeInput"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="QR Code decoded successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="qrdata", type="string"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Invalid QR Code"),
     *       @OA\Property(property="data", type="array", example={"data": "provided data"}),
     *     ),
     *   ),
     * )
     */
    /**
     * Decodes the given encoded data for a QR code.
     *
     * @param string $encodedData The encoded data to be decoded.
     * @return array|false The decoded data or false if decoding fails.
     */
    public function decodeForQRCode(string $encodedData): array|false
    {
        try {
            $hashed1 = base64_decode($encodedData);
            if (!$hashed1) return false;
            $guest = $this->authTokens->decode($hashed1);
            return $guest;
        } catch (Exception) {
            return false;
        }
    }

    /**
     * @OA\Get(
     *   path="/userList",
     *   summary="Get the list of users",
     *   description="Retrieves a list of users based on admin authorization.",
     *   @OA\Parameter(
     *     name="admin",
     *     in="query",
     *     required=true,
     *     description="Admin authorization ID",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Parameter(
     *     name="page",
     *     in="query",
     *     required=false,
     *     description="Page number for pagination",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Parameter(
     *     name="per_page",
     *     in="query",
     *     required=false,
     *     description="Number of items per page",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="List of users",
     *     @OA\JsonContent(
     *       @OA\Property(property="users", type="array", @OA\Items(ref="#/components/schemas/UserInfo")),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=401,
     *     description="Unauthorized",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Unauthorized"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=404,
     *     description="Admin not found",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Admin not found"),
     *     ),
     *   ),
     * )
     */
    /**
     * Retrieves a list of users from the database based on the provided admin ID.
     *
     * @param string $admin_id The ID of the admin.
     * @return array|false An array of user records, or false if no records are found.
     */
    public function userList(string $admin_id, int $page = 0, int $per_page = 20): array | false
    {
        $page = max(0, $page - 1);
        $offset = $page * $per_page;
        $sql = "SELECT 
                    COUNT(*) OVER() AS total_rows,
                    id, 
                    name, 
                    telephone, 
                    actual_name, 
                    password_modified
                FROM {$this->tableName} 
                WHERE 
                    admin_ref = :admin_ref 
                AND 
                    archived = 0 
                LIMIT :limit 
                OFFSET :offset
            ";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':admin_ref', $admin_id, PDO::PARAM_INT);
        $stmt->bindParam(':limit', $per_page, PDO::PARAM_INT);
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($result)) return false;
        $total_rows = (int)($result[0]['total_rows']);
        $userList = [];
        foreach ($result as $row) {
            unset($row['total_rows']);
            unset($row['count(id)']);
            $userList[] = (object)$row;
        }
        $finalResult  = [
            'users' => $userList,
            'page' => ++$page,
            'per_page' => $per_page,
            'total_pages' => ceil($total_rows / $per_page), // total pages based on pagination
            'total_items' => $total_rows, // total items without pagination
        ];
        return $finalResult;
    }

    /**
     * @OA\Get(
     *   path="/guestList",
     *   summary="Get list of guests",
     *   description="Retrieves a list of guests based on the provided parameters.",
     *   @OA\Parameter(
     *     name="admin_ref",
     *     in="query",
     *     required=true,
     *     description="Admin Reference ID",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Parameter(
     *     name="page",
     *     in="query",
     *     required=false,
     *     description="Page number (default: 1)",
     *     @OA\Schema(type="integer", default=1),
     *   ),
     *   @OA\Parameter(
     *     name="per_page",
     *     in="query",
     *     required=false,
     *     description="Items per page (default: 20)",
     *     @OA\Schema(type="integer", default=20),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="Guest list retrieved successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="guests", type="array", @OA\Items(ref="#/components/schemas/GuestInfo")),
     *       @OA\Property(property="total_pages", type="integer"),
     *       @OA\Property(property="total_items", type="integer"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     *   @OA\Response(
     *     response=401,
     *     description="Unauthorized",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Unauthorized"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=404,
     *     description="Admin not found",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Admin not found"),
     *     ),
     *   ),
     * )
     */
    /**
     * @OA\Get(
     *   path="/guestList",
     *   summary="Get list of guests",
     *   description="Retrieves a list of guests based on the provided parameters.",
     *   @OA\Parameter(
     *     name="admin_ref",
     *     in="query",
     *     required=true,
     *     description="Admin Reference ID",
     *     @OA\Schema(type="integer"),
     *   ),
     *   @OA\Parameter(
     *     name="page",
     *     in="query",
     *     required=false,
     *     description="Page number (default: 1)",
     *     @OA\Schema(type="integer", default=1),
     *   ),
     *   @OA\Parameter(
     *     name="per_page",
     *     in="query",
     *     required=false,
     *     description="Items per page (default: 20)",
     *     @OA\Schema(type="integer", default=20),
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="Guest list retrieved successfully",
     *     @OA\JsonContent(
     *       @OA\Property(property="guests", type="array", @OA\Items(ref="#/components/schemas/GuestInfo")),
     *       @OA\Property(property="total_pages", type="integer"),
     *       @OA\Property(property="total_items", type="integer"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=400,
     *     description="Bad request",
     *     @OA\JsonContent(ref="#/components/schemas/ValidationErrors"),
     *   ),
     *   @OA\Response(
     *     response=401,
     *     description="Unauthorized",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Unauthorized"),
     *     ),
     *   ),
     *   @OA\Response(
     *     response=404,
     *     description="Admin not found",
     *     @OA\JsonContent(
     *       @OA\Property(property="error", type="string", example="Admin not found"),
     *     ),
     *   ),
     * )
     */
    public function guestList(int $admin_id, int $page = 0, int $per_page = 20)
    {
        $page = max(0, $page - 1);
        $offset = $page * $per_page;
        $sql = "SELECT 
                    COUNT(*) OVER() AS total_rows,
                    id, 
                    actual_name, 
                    table_number, 
                    telephone, 
                    present,
                    is_out
                FROM {$this->guestTable} 
                WHERE 
                    admin_ref = :admin_ref 
                AND 
                    archived = 0 
                LIMIT :limit 
                OFFSET :offset
            ";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':admin_ref', $admin_id, PDO::PARAM_INT);
        $stmt->bindParam(':limit', $per_page, PDO::PARAM_INT);
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($result)) return false;
        $total_rows = (int)($result[0]['total_rows']);
        $userList = [];
        foreach ($result as $row) {
            unset($row['total_rows']);
            unset($row['count(id)']);
            $userList[] = (object)$row;
        }
        $finalResult  = [
            'users' => $userList,
            'page' => ++$page,
            'per_page' => $per_page,
            'total_pages' => ceil($total_rows / $per_page), // total pages based on pagination
            'total_items' => $total_rows, // total items without pagination
        ];
        return $finalResult;
    }

    /**
     * Retrieves the admin name for which the number equals the admin_id.
     *
     * @param int $admin_id The admin ID to search for.
     * @return string|false The admin name if found, false otherwise.
     */
    private function getAdminName(int $admin_id): string|false
    {
        $sql = "SELECT name FROM {$this->adminTableName} WHERE id = :admin_id AND archived = 0";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindParam(':admin_id', $admin_id);
        $stmt->execute();
        $result = $stmt->fetchColumn();
        if (!$result) return false;
        return $result;
    }

    /**
     * Retrieves the last row from a table with a name similar to the given name.
     *
     * @param string $tableName The name of the table.
     * @param string $givenName The given name to search for.
     * @return string|false The row if found, false otherwise.
     */
    private function getLastRowByName(string $tableName, string $givenName, bool $isAdmin): string|false
    {
        $sql = "SELECT name FROM {$tableName} WHERE name LIKE :given_name ORDER BY name DESC LIMIT 1";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':given_name', $givenName . ($isAdmin ? '%' : '____'));
        $stmt->execute();
        return $stmt->fetchColumn() ?: false;
    }
}
