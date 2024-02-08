<?php
class Database
{
    /**
     * Constructor for the class.
     *
     * @param string $host The host name or IP address for the database connection.
     * @param string $user The username for the database connection.
     * @param string $password The password for the database connection.
     * @param string $name The name of the database.
     * @param string $port The port number for the database connection. Default is "3306".
     */
    public function __construct(private string $host, private string $user, private string $password, private string $name, private string $port = "3306")
    {
    }

    /**
     * Connects to the database and returns a PDO object.
     *
     * @return \PDO|null The PDO object representing the database connection, or null if there is an error connecting.
     * @throws \PDOException If there is an error connecting to the database.
     */
    public function connect(): ?PDO
    {
        $conn = null;

        $str = $this->port == "3306"
            ? "mysql:host={$this->host};dbname={$this->name};charset=utf8"
            : "mysql:host={$this->host};port={$this->port};dbname={$this->name};charset=utf8";
        try {
            $conn = new PDO($str, $this->user, $this->password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_STRINGIFY_FETCHES => false
            ]);
        } catch (PDOException $e) {
            echo 'Connectio Error: ' . $e->getMessage();
        }

        return $conn;
    }
}
