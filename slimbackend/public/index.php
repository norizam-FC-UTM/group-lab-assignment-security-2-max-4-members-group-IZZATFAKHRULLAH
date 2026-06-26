<?php
// ==========================================================
// SECJ3483 Web Technology
// Person BMI Insecure Slim Backend Starter
// ==========================================================
// NOTA:
// This backend is intentionally insecure.
// provided for investigation and fixing during lab activiy this week.
// Do NOT use this code in real applications.
// ==========================================================

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/db.php';

$app = AppFactory::create();

// Required for JSON/form body parsing in Slim 4.
$app->addBodyParsingMiddleware();

// Helpful for development error display.
// INSECURE: In production, detailed errors should not be shown to users.
$app->addErrorMiddleware(true, true, true);

// ----------------------------------------------------------
// CORS for Vue CLI frontend
// ----------------------------------------------------------
$app->add(function (Request $request, $handler) {
    if ($request->getMethod() === 'OPTIONS') {
        $response = new \Slim\Psr7\Response();
    } else {
        $response = $handler->handle($request);
    }

    return $response
        ->withHeader('Access-Control-Allow-Origin', '*') // INSECURE: convenient untuk aktiviti lab, tidak untuk production.
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->withHeader('Access-Control-Allow-Credentials', 'false');
});

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------
function jsonResponse(Response $response, $data, int $status = 200): Response
{
    $response->getBody()->write(json_encode($data, JSON_PRETTY_PRINT));

    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus($status);
}

//
function getRequestData(Request $request): array
{
    $data = $request->getParsedBody();

    if (is_array($data) && !empty($data)) {
        return $data;
    }

    $rawBody = (string) $request->getBody();

    if ($rawBody !== '') {
        $jsonData = json_decode($rawBody, true);

        if (is_array($jsonData)) {
            return $jsonData;
        }
    }

    return is_array($data) ? $data : [];
}

function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64UrlDecode(string $data): string|false
{
    $padding = strlen($data) % 4;
    if ($padding > 0) {
        $data .= str_repeat('=', 4 - $padding);
    }

    return base64_decode(strtr($data, '-_', '+/'), true);
}

function getJwtSecret(): string
{
    return 'SECJ3483_PERSON_BMI_LAB_SECRET';
}

function createJwtToken(array $user): string
{
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];

    $issuedAt = time();
    $payload = [
        'user_id' => $user['id'],
        'role' => $user['role'],
        'iat' => $issuedAt,
        'exp' => $issuedAt + 3600
    ];

    $headerPart = base64UrlEncode(json_encode($header));
    $payloadPart = base64UrlEncode(json_encode($payload));
    $signature = hash_hmac('sha256', "$headerPart.$payloadPart", getJwtSecret(), true);

    return "$headerPart.$payloadPart." . base64UrlEncode($signature);
}

function verifyTokenFromRequest(Request $request): ?array
{
    $auth = $request->getHeaderLine('Authorization');

    if (!$auth || !preg_match('/Bearer\s+(\S+)/', $auth, $matches)) {
        return null;
    }

    $parts = explode('.', $matches[1]);
    if (count($parts) !== 3) {
        return null;
    }

    [$headerPart, $payloadPart, $signaturePart] = $parts;
    $expectedSignature = base64UrlEncode(hash_hmac('sha256', "$headerPart.$payloadPart", getJwtSecret(), true));

    if (!hash_equals($expectedSignature, $signaturePart)) {
        return null;
    }

    $payloadJson = base64UrlDecode($payloadPart);
    if ($payloadJson === false) {
        return null;
    }

    $payload = json_decode($payloadJson, true);
    if (!is_array($payload) || empty($payload['user_id']) || empty($payload['role'])) {
        return null;
    }

    if (($payload['exp'] ?? 0) < time()) {
        return null;
    }

    return $payload;
}

function requireAuth(Request $request, Response $response): array|Response
{
    $decoded = verifyTokenFromRequest($request);

    if (!$decoded) {
        return jsonResponse($response, ['error' => 'Unauthorized'], 401);
    }

    return $decoded;
}

function exposeException(Response $response, Throwable $e): Response
{
    // INSECURE: exposes detailed internal error to API client.
    return jsonResponse($response, [
        'error' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine()
    ], 500);
}

function validateBmiData(array $data, bool $requireAllFields = true): array
{
    $errors = [];

    if ($requireAllFields || array_key_exists('name', $data)) {
        $name = trim((string) ($data['name'] ?? ''));
        if ($name === '') {
            $errors['name'] = 'Name is required';
        }
    }

    if ($requireAllFields || array_key_exists('age', $data)) {
        $age = $data['age'] ?? null;
        if (!is_numeric($age) || (int) $age < 1 || (int) $age > 120) {
            $errors['age'] = 'Age must be between 1 and 120';
        }
    }

    if ($requireAllFields || array_key_exists('height', $data)) {
        $height = $data['height'] ?? null;
        if (!is_numeric($height) || (float) $height < 0.5 || (float) $height > 2.5) {
            $errors['height'] = 'Height must be between 0.5 and 2.5 meters';
        }
    }

    if ($requireAllFields || array_key_exists('weight', $data)) {
        $weight = $data['weight'] ?? null;
        if (!is_numeric($weight) || (float) $weight < 2 || (float) $weight > 300) {
            $errors['weight'] = 'Weight must be between 2 and 300 kg';
        }
    }

    return $errors;
}

function calculateBmi(float $height, float $weight): float
{
    return round($weight / ($height * $height), 2);
}

function getBmiCategory(float $bmi): string
{
    if ($bmi < 18.5) {
        return 'Underweight';
    } elseif ($bmi < 25) {
        return 'Normal';
    } elseif ($bmi < 30) {
        return 'Overweight';
    }

    return 'Obese';
}

function safeUser(array $user): array
{
    return [
        'id' => $user['id'],
        'name' => $user['name'],
        'email' => $user['email'],
        'role' => $user['role'],
        'created_at' => $user['created_at'] ?? null
    ];
}

function canViewPersonRecord(array $currentUser, array $person): bool
{
    $currentUserId = (int) ($currentUser['user_id'] ?? 0);
    $recordOwnerId = (int) ($person['user_id'] ?? 0);
    $role = $currentUser['role'] ?? 'user';

    return $currentUserId === $recordOwnerId || in_array($role, ['staff', 'admin'], true);
}

function canModifyPersonRecord(array $currentUser, array $person): bool
{
    $currentUserId = (int) ($currentUser['user_id'] ?? 0);
    $recordOwnerId = (int) ($person['user_id'] ?? 0);
    $role = $currentUser['role'] ?? 'user';

    return $currentUserId === $recordOwnerId || $role === 'admin';
}

function requireRole(Request $request, Response $response, array $allowedRoles): ?Response
{
    $decoded = verifyTokenFromRequest($request);

    if (!$decoded) {
        return jsonResponse($response, ['error' => 'Unauthorized'], 401);
    }

    $role = $decoded['role'] ?? 'user';
    if (!in_array($role, $allowedRoles, true)) {
        $error = count($allowedRoles) === 1 && $allowedRoles[0] === 'admin'
            ? 'Admin access required'
            : 'Staff access required';

        return jsonResponse($response, ['error' => $error], 403);
    }

    return null;
}

// ----------------------------------------------------------
// Root routes 
// ----------------------------------------------------------
$app->get('/', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'message' => 'Person BMI Insecure Slim Backend Starter',
        'warning' => 'This backend is intentionally insecure for classroom investigation.'
    ]);
});

$app->get('/api/health', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'status' => 'ok',
        'api' => 'person-bmi-insecure-backend'
    ]);
});

// ----------------------------------------------------------
// Public route: Register
// ----------------------------------------------------------
$app->post('/api/register', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $name = $data['name'] ?? '';
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';
        $role = $data['role'] ?? 'user';
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $sql = "INSERT INTO users (name, email, password, password_hash, role)
                VALUES (?, ?, NULL, ?, ?)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$name, $email, $passwordHash, $role]);
        $id = $pdo->lastInsertId();

        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User registered.',
            'user' => safeUser($user),
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Public route: Login
// ----------------------------------------------------------
$app->post('/api/login', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $sql = "SELECT * FROM users WHERE email = ? LIMIT 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        $validPassword = $user && password_verify($password, (string) $user['password_hash']);

        if (!$validPassword && $user && hash_equals((string) $user['password_hash'], (string) $password)) {
            $validPassword = true;
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $updateStmt = $pdo->prepare("UPDATE users SET password = NULL, password_hash = ? WHERE id = ?");
            $updateStmt->execute([$passwordHash, $user['id']]);
            $user['password'] = null;
            $user['password_hash'] = $passwordHash;
        }

        if (!$validPassword) {
            return jsonResponse($response, [
                'error' => 'Invalid login',
                'debug_received_body' => $data,
                'debug_sql' => $sql
            ], 401);
        }

        $token = createJwtToken($user);

        return jsonResponse($response, [
            'message' => 'Login successful.',
            'token' => $token,
            'user' => safeUser($user),
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Protected-ish route: Profile
// ----------------------------------------------------------
$app->get('/api/profile', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $decoded = requireAuth($request, $response);
        if ($decoded instanceof Response) {
            return $decoded;
        }

        $userId = (int) $decoded['user_id'];

        $sql = "SELECT * FROM users WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'Profile returned.',
            'user' => $user ? safeUser($user) : null
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// BMI routes
// ----------------------------------------------------------
$app->get('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $decoded = requireAuth($request, $response);
        if ($decoded instanceof Response) {
            return $decoded;
        }

        $userId = (int) $decoded['user_id'];
        $sql = "SELECT * FROM persons WHERE user_id = ? ORDER BY id DESC";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$userId]);
        $persons = $stmt->fetchAll();

        return jsonResponse($response, [
            'message' => 'Own BMI records returned.',
            'persons' => $persons,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->post('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);
        $decoded = requireAuth($request, $response);

        if ($decoded instanceof Response) {
            return $decoded;
        }

        $validationErrors = validateBmiData($data);
        if ($validationErrors) {
            return jsonResponse($response, [
                'error' => 'Invalid BMI data',
                'details' => $validationErrors
            ], 400);
        }

        $user_id = (int) $decoded['user_id'];
        $name = $data['name'] ?? '';
        $age = $data['age'] ?? 0;
        $height = $data['height'] ?? 0;
        $weight = $data['weight'] ?? 0;
        $bmi = calculateBmi((float) $height, (float) $weight);
        $category = getBmiCategory($bmi);
        $notes = $data['notes'] ?? '';

        $sql = "INSERT INTO persons (user_id, name, age, height, weight, bmi, category, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$user_id, $name, $age, $height, $weight, $bmi, $category, $notes]);
        $id = $pdo->lastInsertId();

        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record created. Backend calculated BMI and category.',
            'person' => $person,
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $decoded = requireAuth($request, $response);

        if ($decoded instanceof Response) {
            return $decoded;
        }

        $sql = "SELECT * FROM persons WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        if (!canViewPersonRecord($decoded, $person)) {
            return jsonResponse($response, ['error' => 'Access denied'], 403);
        }

        return jsonResponse($response, [
            'message' => 'BMI record returned.',
            'person' => $person,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $data = getRequestData($request);
        $decoded = requireAuth($request, $response);

        if ($decoded instanceof Response) {
            return $decoded;
        }

        $validationErrors = validateBmiData($data, false);
        if ($validationErrors) {
            return jsonResponse($response, [
                'error' => 'Invalid BMI data',
                'details' => $validationErrors
            ], 400);
        }

        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmt->execute([$id]);
        $existingPerson = $stmt->fetch();

        if (!$existingPerson) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        if (!canModifyPersonRecord($decoded, $existingPerson)) {
            return jsonResponse($response, ['error' => 'Access denied'], 403);
        }

        // INSECURE MASS ASSIGNMENT:
        // Updates almost any field sent by the frontend.
        // You should whitelist allowed fields and calculate bmi/category at backend.
        $allowedInInsecureStarter = [
            'user_id',
            'name',
            'age',
            'height',
            'weight',
            'notes'
        ];

        $sets = [];
        $values = [];

        foreach ($allowedInInsecureStarter as $field) {
            if (array_key_exists($field, $data)) {
                $value = $data[$field];
                $sets[] = "$field = ?";
                $values[] = $value;
            }
        }

        if (array_key_exists('height', $data) || array_key_exists('weight', $data)) {
            $height = array_key_exists('height', $data) ? (float) $data['height'] : (float) $existingPerson['height'];
            $weight = array_key_exists('weight', $data) ? (float) $data['weight'] : (float) $existingPerson['weight'];
            $bmi = calculateBmi($height, $weight);
            $category = getBmiCategory($bmi);
            $sets[] = "bmi = ?";
            $sets[] = "category = ?";
            $values[] = $bmi;
            $values[] = $category;
        }

        if (!$sets) {
            return jsonResponse($response, [
                'error' => 'No fields to update',
                'debug_received_body' => $data
            ], 400);
        }

        $sql = "UPDATE persons SET " . implode(', ', $sets) . " WHERE id = ?";
        $values[] = $id;
        $stmt = $pdo->prepare($sql);
        $stmt->execute($values);

        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record updated. Backend recalculated BMI and category when height or weight changed.',
            'person' => $person,
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $decoded = requireAuth($request, $response);

        if ($decoded instanceof Response) {
            return $decoded;
        }

        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        if (!canModifyPersonRecord($decoded, $person)) {
            return jsonResponse($response, ['error' => 'Access denied'], 403);
        }

        $sql = "DELETE FROM persons WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$id]);

        return jsonResponse($response, [
            'message' => 'BMI record deleted.',
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Staff routes
// ----------------------------------------------------------
$app->get('/api/staff/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $roleError = requireRole($request, $response, ['staff', 'admin']);
        if ($roleError) {
            return $roleError;
        }

        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                ORDER BY persons.id DESC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $persons = $stmt->fetchAll();

        return jsonResponse($response, [
            'message' => 'All BMI records returned for staff monitoring.',
            'persons' => $persons,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/staff/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        $roleError = requireRole($request, $response, ['staff', 'admin']);
        if ($roleError) {
            return $roleError;
        }

        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                WHERE persons.id = ?";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        return jsonResponse($response, [
            'message' => 'Staff BMI record returned.',
            'person' => $person,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Admin routes
// ----------------------------------------------------------
$app->get('/api/admin/users', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $roleError = requireRole($request, $response, ['admin']);
        if ($roleError) {
            return $roleError;
        }

        // SELECT * still exposes password/password_hash. This is fixed in the next response-cleanup commit.
        $sql = "SELECT * FROM users ORDER BY id ASC";
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $users = $stmt->fetchAll();

        return jsonResponse($response, [
            'message' => 'All users returned for admin. Sensitive fields still need a later fix.',
            'users' => $users,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/admin/users/{id}/role', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $data = getRequestData($request);
        $role = $data['role'] ?? 'user';

        $roleError = requireRole($request, $response, ['admin']);
        if ($roleError) {
            return $roleError;
        }

        $sql = "UPDATE users SET role = ? WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$role, $id]);

        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User role changed by admin.',
            'user' => $user,
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/admin/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        $roleError = requireRole($request, $response, ['admin']);
        if ($roleError) {
            return $roleError;
        }

        $sql = "DELETE FROM persons WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$id]);

        return jsonResponse($response, [
            'message' => 'Admin delete executed.',
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// Preflight catch-all
$app->options('/{routes:.+}', function (Request $request, Response $response) {
    return $response;
});

$app->run();
