<?php
session_start();

// Security Headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");

$db_host = '127.0.0.1';
$db_name = 'job_commission';
$db_user = 'root';
$db_pass = ''; 
$commission_percent = 10.0;

try {
    $pdo = new PDO("mysql:host={$db_host};dbname={$db_name};charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (Exception $e) {
    die("Database connection failed: " . htmlspecialchars($e->getMessage()));
}

// Initialize database tables
function initialize_database($pdo) {
    $queries = [
        // Users table
        "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            phone VARCHAR(20),
            address TEXT,
            city VARCHAR(50),
            state VARCHAR(50),
            country VARCHAR(50),
            postal_code VARCHAR(20),
            bio TEXT,
            skills TEXT,
            profile_picture VARCHAR(255),
            password VARCHAR(255) NOT NULL,
            type ENUM('employer', 'freelancer') NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )",
        
        // Jobs table
        "CREATE TABLE IF NOT EXISTS jobs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employer_id INT NOT NULL,
            title VARCHAR(200) NOT NULL,
            description TEXT NOT NULL,
            budget DECIMAL(10,2) NOT NULL,
            job_type ENUM('one-time', 'ongoing', 'hourly') NOT NULL,
            category VARCHAR(100),
            skills_required TEXT,
            experience_level ENUM('entry', 'intermediate', 'expert') NOT NULL,
            duration VARCHAR(50),
            job_address TEXT,
            job_city VARCHAR(50),
            job_state VARCHAR(50),
            job_country VARCHAR(50),
            remote_ok BOOLEAN DEFAULT FALSE,
            status ENUM('open', 'assigned', 'in_progress', 'completed', 'cancelled') DEFAULT 'open',
            assigned_application_id INT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        
        // Applications table
        "CREATE TABLE IF NOT EXISTS applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            job_id INT NOT NULL,
            freelancer_id INT NOT NULL,
            proposal TEXT NOT NULL,
            bid DECIMAL(10,2) NOT NULL,
            estimated_days INT NOT NULL,
            status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
            FOREIGN KEY (freelancer_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        
        // Messages table
        "CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sender_id INT NOT NULL,
            receiver_id INT NOT NULL,
            job_id INT NOT NULL,
            message TEXT NOT NULL,
            parent_message_id INT NULL,
            read_status BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_message_id) REFERENCES messages(id) ON DELETE SET NULL
        )",
        
        // Rate limits table
        "CREATE TABLE IF NOT EXISTS rate_limits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            user_id INT NULL,
            action VARCHAR(50) NOT NULL,
            created_at DATETIME NOT NULL,
            INDEX idx_ip_action (ip_address, action),
            INDEX idx_created_at (created_at)
        )"
    ];
    
    foreach ($queries as $query) {
        try {
            $pdo->exec($query);
        } catch (Exception $e) {
            // Ignore errors for existing tables
        }
    }
}

// Initialize database on first run
initialize_database($pdo);

// ---------------------------
// SECURITY PROTECTION FUNCTIONS
// ---------------------------

// Free Email Verification using disposable email detection
function is_disposable_email($email) {
    $disposable_domains = [
        'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
        'throwawaymail.com', 'fakeinbox.com', 'yopmail.com', 'getairmail.com',
        'tmpmail.org', 'trashmail.com', 'dispostable.com', 'mailnesia.com',
        'grr.la', 'guerrillamail.net', 'sharklasers.com', 'guerrillamail.biz',
        'guerrillamail.org', 'pokemail.net', 'spam4.me', 'spamgourmet.com'
    ];
    
    $domain = strtolower(substr(strrchr($email, "@"), 1));
    return in_array($domain, $disposable_domains);
}

// Free Phone Validation (basic pattern + length check)
function validate_real_phone($phone) {
    // Remove all non-digit characters
    $clean_phone = preg_replace('/[^0-9]/', '', $phone);
    
    // Check length (international numbers typically 10-15 digits)
    if (strlen($clean_phone) < 10 || strlen($clean_phone) > 15) {
        return "Phone number must be between 10-15 digits";
    }
    
    // Check for obvious fake patterns
    $fake_patterns = [
        '/^1234567890$/',
        '/^1111111111$/',
        '/^0000000000$/',
        '/^5555555555$/',
        '/^(\d)\1{9,}$/' // All same digits
    ];
    
    foreach ($fake_patterns as $pattern) {
        if (preg_match($pattern, $clean_phone)) {
            return "Invalid phone number pattern detected";
        }
    }
    
    return null;
}

// IP-based rate limiting
function check_rate_limit($pdo, $user_id = null, $action = 'general', $max_attempts = 5, $time_window = 3600) {
    $ip = $_SERVER['REMOTE_ADDR'];
    
    // Clean old records
    $pdo->prepare("DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)")->execute();
    
    // Check current attempts
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as attempts 
        FROM rate_limits 
        WHERE ip_address = ? AND action = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
    ");
    $stmt->execute([$ip, $action, $time_window]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($result['attempts'] >= $max_attempts) {
        return "Rate limit exceeded. Please try again later.";
    }
    
    // Record this attempt
    $stmt = $pdo->prepare("INSERT INTO rate_limits (ip_address, user_id, action, created_at) VALUES (?, ?, ?, NOW())");
    $stmt->execute([$ip, $user_id, $action]);
    
    return null;
}

// User behavior analysis
function analyze_user_behavior($pdo, $user_id) {
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_jobs,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_jobs,
            SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled_jobs
        FROM jobs 
        WHERE employer_id = ?
    ");
    $stmt->execute([$user_id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Enhanced fraud detection
function detect_fraud_patterns($pdo, $user_data) {
    $red_flags = [];
    
    // Check for recently created accounts with high activity
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as job_count 
        FROM jobs 
        WHERE employer_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)
    ");
    $stmt->execute([$user_data['id']]);
    $recent_jobs = $stmt->fetchColumn();
    
    if ($recent_jobs > 5) {
        $red_flags[] = "High job posting frequency for new account";
    }
    
    // Check for similar job titles/descriptions
    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT title) as unique_titles, COUNT(*) as total_jobs
        FROM jobs 
        WHERE employer_id = ?
    ");
    $stmt->execute([$user_data['id']]);
    $title_stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($title_stats['total_jobs'] > 3 && $title_stats['unique_titles'] / $title_stats['total_jobs'] < 0.5) {
        $red_flags[] = "Low diversity in job titles";
    }
    
    return $red_flags;
}

// Free IP reputation check (basic)
function check_ip_reputation($ip) {
    // Allow all IPs for now to fix registration issue
    return "clean";
}

// ---------------------------
// Helpers
// ---------------------------
function is_logged_in() {
    return isset($_SESSION['user_id']);
}

function current_user($pdo) {
    if(!is_logged_in()) return null;
    $stmt = $pdo->prepare("SELECT id, username, name, email, phone, address, city, state, country, postal_code, bio, skills, profile_picture, type, created_at FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function flash($msg, $type='info') {
    $_SESSION['flash'] = ['msg'=>$msg,'type'=>$type];
}

function get_flash() {
    if(isset($_SESSION['flash'])) { $f=$_SESSION['flash']; unset($_SESSION['flash']); return $f; }
    return null;
}

function esc($s){ return htmlspecialchars($s ?? ''); }

function validate_password($password) {
    if(strlen($password) < 8) {
        return "Password must be at least 8 characters long";
    }
    if(!preg_match('/[A-Z]/', $password)) {
        return "Password must contain at least one uppercase letter";
    }
    if(!preg_match('/[a-z]/', $password)) {
        return "Password must contain at least one lowercase letter";
    }
    if(!preg_match('/[0-9]/', $password)) {
        return "Password must contain at least one number";
    }
    if(!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        return "Password must contain at least one special character";
    }
    return null;
}

function validate_username($username) {
    if(strlen($username) < 3) {
        return "Username must be at least 3 characters long";
    }
    if(!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        return "Username can only contain letters, numbers, and underscores";
    }
    return null;
}

function validate_email($email) {
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return "Invalid email format";
    }
    
    // Enhanced: Check for disposable email
    if (is_disposable_email($email)) {
        return "Disposable email addresses are not allowed for security reasons";
    }
    
    return null;
}

function validate_phone($phone) {
    if(!preg_match('/^[\+]?[0-9\s\-\(\)]{10,}$/', $phone)) {
        return "Invalid phone number format";
    }
    
    // Enhanced: Real phone validation
    $phone_validation = validate_real_phone($phone);
    if ($phone_validation) {
        return $phone_validation;
    }
    
    return null;
}

// ---------------------------
// Enhanced Notification Functions
// ---------------------------
function get_unread_message_count($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND read_status = 0");
    $stmt->execute([$user_id]);
    return $stmt->fetchColumn();
}

function get_user_notifications($pdo, $user_id) {
    $stmt = $pdo->prepare("
        SELECT m.*, u.name as sender_name, u.id as sender_id, j.title as job_title, j.id as job_id
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        JOIN jobs j ON m.job_id = j.id 
        WHERE m.receiver_id = ? AND m.read_status = 0 
        ORDER BY m.created_at DESC
    ");
    $stmt->execute([$user_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function mark_message_as_read($pdo, $message_id) {
    $stmt = $pdo->prepare("UPDATE messages SET read_status = 1 WHERE id = ?");
    $stmt->execute([$message_id]);
}

function mark_conversation_as_read($pdo, $user_id, $other_user_id, $job_id) {
    $stmt = $pdo->prepare("UPDATE messages SET read_status = 1 WHERE receiver_id = ? AND sender_id = ? AND job_id = ? AND read_status = 0");
    $stmt->execute([$user_id, $other_user_id, $job_id]);
}

function get_conversations($pdo, $user_id) {
    $stmt = $pdo->prepare("
        SELECT 
            u.id as other_user_id,
            u.name as other_user_name,
            u.type as other_user_type,
            j.id as job_id,
            j.title as job_title,
            MAX(m.created_at) as last_message_time,
            COUNT(CASE WHEN m.read_status = 0 AND m.receiver_id = ? THEN 1 END) as unread_count,
            (SELECT message FROM messages m2 
             WHERE ((m2.sender_id = ? AND m2.receiver_id = u.id) OR (m2.sender_id = u.id AND m2.receiver_id = ?))
             AND m2.job_id = j.id 
             ORDER BY m2.created_at DESC LIMIT 1) as last_message
        FROM messages m
        JOIN users u ON (u.id = m.sender_id OR u.id = m.receiver_id) AND u.id != ?
        JOIN jobs j ON m.job_id = j.id
        WHERE ? IN (m.sender_id, m.receiver_id)
        GROUP BY u.id, j.id
        ORDER BY last_message_time DESC
    ");
    $stmt->execute([$user_id, $user_id, $user_id, $user_id, $user_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function get_conversation_messages($pdo, $user_id, $other_user_id, $job_id) {
    $stmt = $pdo->prepare("
        SELECT m.*,
               sender.name as sender_name,
               receiver.name as receiver_name,
               j.title as job_title
        FROM messages m
        JOIN users sender ON m.sender_id = sender.id
        JOIN users receiver ON m.receiver_id = receiver.id
        JOIN jobs j ON m.job_id = j.id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        AND m.job_id = ?
        ORDER BY m.created_at ASC
    ");
    $stmt->execute([$user_id, $other_user_id, $other_user_id, $user_id, $job_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// ---------------------------
// Simple router via ?action=...
// ---------------------------
$action = $_REQUEST['action'] ?? 'home';

// ---------------------------
// AUTH: register / login / logout
// ---------------------------
if($action === 'register' && $_SERVER['REQUEST_METHOD']==='POST') {
    // Rate limiting for registration
   // $rate_limit = check_rate_limit($pdo, null, 'register', 3, 3600);
   // if ($rate_limit) {
       // flash($rate_limit, 'danger');
      //  header("Location: ?action=home#auth");
      //  exit;
  //  }
    
    $username = trim($_POST['username'] ?? '');
    $name = trim($_POST['name'] ?? '');
    $email = strtolower(trim($_POST['email'] ?? ''));
    $phone = trim($_POST['phone'] ?? '');
    $address = trim($_POST['address'] ?? '');
    $city = trim($_POST['city'] ?? '');
    $state = trim($_POST['state'] ?? '');
    $country = trim($_POST['country'] ?? '');
    $postal_code = trim($_POST['postal_code'] ?? '');
    $bio = trim($_POST['bio'] ?? '');
    $skills = trim($_POST['skills'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $type = ($_POST['type'] === 'employer') ? 'employer' : 'freelancer';

    // Validation
    $errors = [];
    
    // Required fields
    if(!$username) $errors[] = "Username is required";
    if(!$name) $errors[] = "Full name is required";
    if(!$email) $errors[] = "Email is required";
    if(!$password) $errors[] = "Password is required";
    if(!$confirm_password) $errors[] = "Confirm password is required";
    
    // Custom validations
    if($username) {
        $username_error = validate_username($username);
        if($username_error) $errors[] = $username_error;
    }
    
    if($email) {
        $email_error = validate_email($email);
        if($email_error) $errors[] = $email_error;
    }
    
    if($phone) {
        $phone_error = validate_phone($phone);
        if($phone_error) $errors[] = $phone_error;
    }
    
    if($password) {
        $password_error = validate_password($password);
        if($password_error) $errors[] = $password_error;
    }
    
    if($password !== $confirm_password) {
        $errors[] = "Passwords do not match";
    }

    // IP reputation check
    $ip_reputation = check_ip_reputation($_SERVER['REMOTE_ADDR']);
    if ($ip_reputation === 'suspicious') {
        $errors[] = "Registration not allowed from this network";
    }

    // Check if username or email already exists
    if($username) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if($stmt->fetchColumn() > 0) {
            $errors[] = "Username already exists";
        }
    }
    
    if($email) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if($stmt->fetchColumn() > 0) {
            $errors[] = "Email already exists";
        }
    }

    if(!empty($errors)) {
        $_SESSION['form_data'] = $_POST;
        flash(implode("<br>", $errors), 'danger');
        header("Location: ?action=home#auth");
        exit;
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, name, email, phone, address, city, state, country, postal_code, bio, skills, password, type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");
        $stmt->execute([$username, $name, $email, $phone, $address, $city, $state, $country, $postal_code, $bio, $skills, $hash, $type]);
        unset($_SESSION['form_data']);
        flash("Registration successful. Please login.", 'success');
    } catch (Exception $e){
        flash("Registration failed: " . $e->getMessage(), 'danger');
    }
    header("Location: ?action=home#auth"); exit;
}

if($action === 'login' && $_SERVER['REQUEST_METHOD']==='POST') {
    // Rate limiting for login
    //$rate_limit = check_rate_limit($pdo, null, 'login', 5, 900);
    //if ($rate_limit) {
        //flash($rate_limit, 'danger');
        //header("Location: ?action=home#auth");
       // exit;
   // }
    
    
    $login = trim($_POST['login'] ?? ''); // Can be username or email
    $password = $_POST['password'] ?? '';
    
    // Determine if login is email or username
    $is_email = filter_var($login, FILTER_VALIDATE_EMAIL);
    $field = $is_email ? 'email' : 'username';
    
    $stmt = $pdo->prepare("SELECT id, password FROM users WHERE $field = ?");
    $stmt->execute([$login]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if($u && password_verify($password, $u['password'])) {
        $_SESSION['user_id'] = $u['id'];
        
        // Security check: Analyze user behavior
        $user = current_user($pdo);
        $fraud_flags = detect_fraud_patterns($pdo, $user);
        if (!empty($fraud_flags)) {
            // Log security flags but don't block login
            error_log("Security flags for user {$user['id']}: " . implode(", ", $fraud_flags));
        }
        
        flash("Welcome back!", 'success');
        header("Location: ?action=dashboard"); exit;
    } else {
        flash("Invalid credentials.", 'danger');
        header("Location: ?action=home#auth"); exit;
    }
}

if($action === 'logout') {
    session_destroy();
    session_start();
    flash("Logged out.", 'info');
    header("Location: ?action=home"); exit;
}

// ---------------------------
// Profile Update
// ---------------------------
if($action === 'update_profile' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    
    $user = current_user($pdo);
    $name = trim($_POST['name'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $address = trim($_POST['address'] ?? '');
    $city = trim($_POST['city'] ?? '');
    $state = trim($_POST['state'] ?? '');
    $country = trim($_POST['country'] ?? '');
    $postal_code = trim($_POST['postal_code'] ?? '');
    $bio = trim($_POST['bio'] ?? '');
    $skills = trim($_POST['skills'] ?? '');

    // Validation
    $errors = [];
    if(!$name) $errors[] = "Full name is required";
    
    if($phone) {
        $phone_error = validate_phone($phone);
        if($phone_error) $errors[] = $phone_error;
    }

    if(!empty($errors)) {
        flash(implode("<br>", $errors), 'danger');
        header("Location: ?action=profile");
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE users SET name=?, phone=?, address=?, city=?, state=?, country=?, postal_code=?, bio=?, skills=? WHERE id=?");
        $stmt->execute([$name, $phone, $address, $city, $state, $country, $postal_code, $bio, $skills, $user['id']]);
        flash("Profile updated successfully.", 'success');
    } catch (Exception $e) {
        flash("Profile update failed: " . $e->getMessage(), 'danger');
    }
    header("Location: ?action=profile"); exit;
}

// ---------------------------
// Employer posts job
// ---------------------------
if($action === 'post_job' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    
    // Rate limiting for job posting
    $user = current_user($pdo);
    $rate_limit = check_rate_limit($pdo, $user['id'], 'post_job', 10, 3600);
    if ($rate_limit) {
        flash($rate_limit, 'danger');
        header("Location: ?action=dashboard");
        exit;
    }
    
    if($user['type'] !== 'employer') { flash("Only employers can post jobs.", 'danger'); header("Location: ?action=dashboard"); exit; }
    
    $title = trim($_POST['title'] ?? '');
    $desc = trim($_POST['description'] ?? '');
    $budget = floatval($_POST['budget'] ?? 0);
    $job_type = $_POST['job_type'] ?? 'one-time';
    $category = trim($_POST['category'] ?? '');
    $skills_required = trim($_POST['skills_required'] ?? '');
    $experience_level = $_POST['experience_level'] ?? 'intermediate';
    $duration = trim($_POST['duration'] ?? '');
    $job_address = trim($_POST['job_address'] ?? '');
    $job_city = trim($_POST['job_city'] ?? '');
    $job_state = trim($_POST['job_state'] ?? '');
    $job_country = trim($_POST['job_country'] ?? '');
    $remote_ok = isset($_POST['remote_ok']) ? 1 : 0;
    
    if(!$title || $budget <= 0) { flash("Title and positive budget required.", 'danger'); header("Location: ?action=dashboard"); exit; }
    
    // Fraud detection for job posting
    $fraud_flags = detect_fraud_patterns($pdo, $user);
    if (!empty($fraud_flags)) {
        // Log suspicious activity but allow posting
        error_log("Suspicious job posting by user {$user['id']}: " . implode(", ", $fraud_flags));
    }
    
    $stmt = $pdo->prepare("INSERT INTO jobs (employer_id, title, description, budget, job_type, category, skills_required, experience_level, duration, job_address, job_city, job_state, job_country, remote_ok) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    $stmt->execute([$user['id'], $title, $desc, $budget, $job_type, $category, $skills_required, $experience_level, $duration, $job_address, $job_city, $job_state, $job_country, $remote_ok]);
    flash("Job posted successfully.", 'success');
    header("Location: ?action=dashboard"); exit;
}

// ---------------------------
// Freelancer applies
// ---------------------------
if($action === 'apply' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    
    // Rate limiting for applications
    $user = current_user($pdo);
    $rate_limit = check_rate_limit($pdo, $user['id'], 'apply', 20, 3600);
    if ($rate_limit) {
        flash($rate_limit, 'danger');
        header("Location: ?action=dashboard");
        exit;
    }
    
    if($user['type'] !== 'freelancer') { flash("Only freelancers can apply.", 'danger'); header("Location: ?action=dashboard"); exit; }
    $job_id = intval($_POST['job_id'] ?? 0);
    $proposal = trim($_POST['proposal'] ?? '');
    $bid = floatval($_POST['bid'] ?? 0);
    $estimated_days = intval($_POST['estimated_days'] ?? 0);
    
    if(!$job_id || $bid <= 0) { flash("Invalid application.", 'danger'); header("Location: ?action=dashboard"); exit; }
    // Check not already applied
    $s = $pdo->prepare("SELECT COUNT(*) FROM applications WHERE job_id=? AND freelancer_id=?");
    $s->execute([$job_id,$user['id']]);
    if($s->fetchColumn() > 0) { flash("You already applied to this job.", 'warning'); header("Location: ?action=dashboard"); exit; }
    
    $stmt = $pdo->prepare("INSERT INTO applications (job_id, freelancer_id, proposal, bid, estimated_days) VALUES (?,?,?,?,?)");
    $stmt->execute([$job_id,$user['id'],$proposal,$bid,$estimated_days]);
    flash("Application submitted successfully.", 'success');
    header("Location: ?action=dashboard"); exit;
}

// ---------------------------
// Employer accepts application
// ---------------------------
if($action === 'accept_application' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    if($user['type'] !== 'employer') { flash("Only employers can accept.", 'danger'); header("Location: ?action=dashboard"); exit; }
    $app_id = intval($_POST['app_id'] ?? 0);
    // Fetch application and job
    $s = $pdo->prepare("SELECT a.*, j.employer_id, j.status as job_status FROM applications a JOIN jobs j ON a.job_id=j.id WHERE a.id=?");
    $s->execute([$app_id]);
    $app = $s->fetch(PDO::FETCH_ASSOC);
    if(!$app || $app['employer_id'] != $user['id']) { flash("Invalid action.", 'danger'); header("Location: ?action=dashboard"); exit; }
    if($app['job_status'] !== 'open') { flash("Job not open.", 'warning'); header("Location: ?action=dashboard"); exit; }
    // Mark application accepted, job assigned
    $pdo->beginTransaction();
    $pdo->prepare("UPDATE applications SET status='accepted' WHERE id=?")->execute([$app_id]);
    $pdo->prepare("UPDATE jobs SET status='assigned', assigned_application_id=? WHERE id=?")->execute([$app['id'],$app['job_id']]);
    // reject other applications
    $pdo->prepare("UPDATE applications SET status='rejected' WHERE job_id=? AND id<>?")->execute([$app['job_id'],$app_id]);
    $pdo->commit();
    flash("Application accepted and job assigned.", 'success');
    header("Location: ?action=dashboard"); exit;
}

// ---------------------------
// Employer marks in_progress or completed
// ---------------------------
if($action === 'update_job_status' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    if($user['type'] !== 'employer') { flash("Only employers can update job status.", 'danger'); header("Location: ?action=dashboard"); exit; }
    $job_id = intval($_POST['job_id'] ?? 0);
    $new_status = $_POST['new_status'] ?? '';
    if(!in_array($new_status, ['in_progress','completed','cancelled'])) { flash("Invalid status.", 'danger'); header("Location: ?action=dashboard"); exit; }
    // Verify ownership
    $s = $pdo->prepare("SELECT * FROM jobs WHERE id=? AND employer_id=?");
    $s->execute([$job_id,$user['id']]);
    $job = $s->fetch(PDO::FETCH_ASSOC);
    if(!$job) { flash("Job not found.", 'danger'); header("Location: ?action=dashboard"); exit; }
    $pdo->prepare("UPDATE jobs SET status=? WHERE id=?")->execute([$new_status,$job_id]);
    flash("Job status updated to {$new_status}.", 'success');
    header("Location: ?action=dashboard"); exit;
}

// ---------------------------
// Enhanced Message Handling
// ---------------------------
if($action === 'send_message' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    
    // Rate limiting for messages
    $user = current_user($pdo);
    $rate_limit = check_rate_limit($pdo, $user['id'], 'send_message', 30, 3600);
    if ($rate_limit) {
        flash($rate_limit, 'danger');
        header("Location: ?action=dashboard");
        exit;
    }
    
    $receiver_id = intval($_POST['receiver_id'] ?? 0);
    $job_id = intval($_POST['job_id'] ?? 0);
    $message = trim($_POST['message'] ?? '');
    
    if(!$receiver_id || !$message) { 
        flash("Receiver and message are required.", 'danger'); 
        header("Location: ?action=dashboard"); 
        exit; 
    }
    
    try {
        $stmt = $pdo->prepare("INSERT INTO messages (sender_id, receiver_id, job_id, message, created_at) VALUES (?, ?, ?, ?, NOW())");
        $stmt->execute([$user['id'], $receiver_id, $job_id, $message]);
        flash("Message sent successfully.", 'success');
    } catch (Exception $e) {
        flash("Failed to send message: " . $e->getMessage(), 'danger');
    }
    
    // Redirect back to conversation
    if(isset($_POST['conversation_redirect'])) {
        header("Location: ?action=conversation&user_id=$receiver_id&job_id=$job_id");
    } else {
        header("Location: ?action=dashboard");
    }
    exit;
}

if($action === 'respond_message' && $_SERVER['REQUEST_METHOD']==='POST') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    
    $receiver_id = intval($_POST['receiver_id'] ?? 0);
    $job_id = intval($_POST['job_id'] ?? 0);
    $response = trim($_POST['response'] ?? '');
    $original_message_id = intval($_POST['original_message_id'] ?? 0);
    
    if(!$receiver_id || !$response) { 
        flash("Receiver and response are required.", 'danger'); 
        header("Location: ?action=dashboard"); 
        exit; 
    }
    
    try {
        $stmt = $pdo->prepare("INSERT INTO messages (sender_id, receiver_id, job_id, message, parent_message_id, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
        $stmt->execute([$user['id'], $receiver_id, $job_id, $response, $original_message_id]);
        flash("Response sent successfully.", 'success');
    } catch (Exception $e) {
        flash("Failed to send response: " . $e->getMessage(), 'danger');
    }
    
    // Redirect back to conversation
    header("Location: ?action=conversation&user_id=$receiver_id&job_id=$job_id");
    exit;
}

// ---------------------------
// Enhanced Notification Handling
// ---------------------------
if($action === 'view_notifications') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    
    // Mark all notifications as read when viewing them
    $stmt = $pdo->prepare("UPDATE messages SET read_status = 1 WHERE receiver_id = ?");
    $stmt->execute([$user['id']]);
    
    header("Location: ?action=messages"); exit;
}

if($action === 'mark_notification_read') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    
    $message_id = intval($_GET['message_id'] ?? 0);
    if($message_id) {
        mark_message_as_read($pdo, $message_id);
    }
    
    // Return JSON response for AJAX calls
    if(isset($_GET['ajax'])) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true]);
        exit;
    }
    
    header("Location: " . ($_SERVER['HTTP_REFERER'] ?? '?action=dashboard'));
    exit;
}

// ---------------------------
// Enhanced Messages Page with Conversations
// ---------------------------
if($action === 'messages') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    
    // Get all conversations
    $conversations = get_conversations($pdo, $user['id']);
    
    render_header($pdo);
    ?>
    <div class="grid">
        <div>
            <div class="card fade-in">
                <h3><i class="fas fa-comments"></i> Message Center</h3>
                
                <?php if($conversations): ?>
                    <div class="conversations-list">
                        <?php foreach($conversations as $conv): ?>
                            <a href="?action=conversation&user_id=<?= $conv['other_user_id'] ?>&job_id=<?= $conv['job_id'] ?>" class="conversation-item">
                                <div class="conversation-avatar">
                                    <?= strtoupper(substr($conv['other_user_name'], 0, 1)) ?>
                                </div>
                                <div class="conversation-info">
                                    <div class="conversation-header">
                                        <strong><?= esc($conv['other_user_name']) ?></strong>
                                        <span class="conversation-time"><?= date('M j, g:i A', strtotime($conv['last_message_time'])) ?></span>
                                    </div>
                                    <div class="conversation-preview">
                                        <span class="job-title"><?= esc($conv['job_title']) ?></span>
                                        <p><?= esc(substr($conv['last_message'], 0, 60)) ?>...</p>
                                    </div>
                                </div>
                                <?php if($conv['unread_count'] > 0): ?>
                                    <span class="conversation-badge"><?= $conv['unread_count'] ?></span>
                                <?php endif; ?>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="no-conversations">
                        <i class="fas fa-comments fa-3x" style="color: var(--gray-light); margin-bottom: 20px;"></i>
                        <h4>No conversations yet</h4>
                        <p>Start a conversation by applying to jobs or contacting freelancers.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <aside>
            <div class="card fade-in">
                <h4><i class="fas fa-info-circle"></i> Message Info</h4>
                <p>Your conversations are organized by job and person. Click on any conversation to view the full message history.</p>
                <p>Unread messages are shown with a red badge.</p>
            </div>
            
            <div class="card fade-in">
                <h4><i class="fas fa-bell"></i> Quick Actions</h4>
                <a href="?action=view_notifications" class="btn" style="width: 100%; margin-bottom: 10px;">
                    <i class="fas fa-check-double"></i> Mark All as Read
                </a>
                <a href="?action=dashboard" class="btn-secondary" style="width: 100%;">
                    <i class="fas fa-tachometer-alt"></i> Back to Dashboard
                </a>
            </div>
        </aside>
    </div>
    
    <style>
        .conversations-list {
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: var(--border-radius);
            overflow: hidden;
        }
        
        .conversation-item {
            display: flex;
            align-items: center;
            padding: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            text-decoration: none;
            color: var(--light);
            transition: var(--transition);
            position: relative;
        }
        
        .conversation-item:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .conversation-item:last-child {
            border-bottom: none;
        }
        
        .conversation-avatar {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 18px;
            margin-right: 15px;
            flex-shrink: 0;
        }
        
        .conversation-info {
            flex: 1;
            min-width: 0;
        }
        
        .conversation-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        
        .conversation-header strong {
            font-size: 1rem;
        }
        
        .conversation-time {
            font-size: 0.8rem;
            color: var(--gray-light);
        }
        
        .conversation-preview {
            font-size: 0.9rem;
            color: var(--gray-light);
        }
        
        .conversation-preview .job-title {
            color: var(--success);
            font-weight: 500;
            font-size: 0.8rem;
        }
        
        .conversation-preview p {
            margin: 5px 0 0 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .conversation-badge {
            background: var(--danger);
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.7rem;
            font-weight: bold;
            margin-left: 10px;
            flex-shrink: 0;
        }
        
        .no-conversations {
            text-align: center;
            padding: 40px 20px;
            color: var(--gray-light);
        }
        
        .no-conversations h4 {
            margin-bottom: 10px;
            color: var(--light);
        }
    </style>
    <?php
    render_footer();
    exit;
}

// ---------------------------
// Individual Conversation Page
// ---------------------------
if($action === 'conversation') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    
    $other_user_id = intval($_GET['user_id'] ?? 0);
    $job_id = intval($_GET['job_id'] ?? 0);
    
    if(!$other_user_id || !$job_id) {
        flash("Invalid conversation.", 'danger');
        header("Location: ?action=messages");
        exit;
    }
    
    // Get other user info
    $stmt = $pdo->prepare("SELECT name, type FROM users WHERE id = ?");
    $stmt->execute([$other_user_id]);
    $other_user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if(!$other_user) {
        flash("User not found.", 'danger');
        header("Location: ?action=messages");
        exit;
    }
    
    // Get job info
    $stmt = $pdo->prepare("SELECT title FROM jobs WHERE id = ?");
    $stmt->execute([$job_id]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if(!$job) {
        flash("Job not found.", 'danger');
        header("Location: ?action=messages");
        exit;
    }
    
    // Mark conversation as read
    mark_conversation_as_read($pdo, $user['id'], $other_user_id, $job_id);
    
    // Get conversation messages
    $messages = get_conversation_messages($pdo, $user['id'], $other_user_id, $job_id);
    
    render_header($pdo);
    ?>
    <div class="grid">
        <div>
            <div class="card fade-in">
                <div class="conversation-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1);">
                    <div>
                        <h3 style="margin: 0;">
                            <i class="fas fa-user"></i> 
                            <?= esc($other_user['name']) ?>
                            <small style="color: var(--gray-light); font-size: 0.9rem;">
                                (<?= esc($other_user['type']) ?>)
                            </small>
                        </h3>
                        <p style="margin: 5px 0 0 0; color: var(--success);">
                            <i class="fas fa-briefcase"></i> <?= esc($job['title']) ?>
                        </p>
                    </div>
                    <a href="?action=messages" class="btn-secondary">
                        <i class="fas fa-arrow-left"></i> Back to Messages
                    </a>
                </div>
                
                <div class="message-thread" id="messageThread" style="max-height: 500px; overflow-y: auto; margin-bottom: 20px;">
                    <?php if($messages): ?>
                        <?php foreach($messages as $msg): ?>
                            <div class="message-bubble <?= $msg['sender_id'] == $user['id'] ? 'sent' : 'received' ?>">
                                <div class="message-content">
                                    <div class="message-text"><?= nl2br(esc($msg['message'])) ?></div>
                                    <div class="message-time">
                                        <?= date('g:i A', strtotime($msg['created_at'])) ?>
                                        <?php if($msg['sender_id'] == $user['id'] && $msg['read_status']): ?>
                                            <i class="fas fa-check-double" style="color: var(--success); margin-left: 5px;"></i>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="no-messages" style="text-align: center; padding: 40px; color: var(--gray-light);">
                            <i class="fas fa-comments fa-3x" style="margin-bottom: 15px;"></i>
                            <p>No messages yet. Start the conversation!</p>
                        </div>
                    <?php endif; ?>
                </div>
                
                <form method="POST" action="?action=send_message" class="message-form">
                    <input type="hidden" name="receiver_id" value="<?= $other_user_id ?>">
                    <input type="hidden" name="job_id" value="<?= $job_id ?>">
                    <input type="hidden" name="conversation_redirect" value="1">
                    <div class="form-group" style="margin-bottom: 0;">
                        <div style="display: flex; gap: 10px;">
                            <textarea name="message" rows="2" placeholder="Type your message..." style="flex: 1; resize: none;" required></textarea>
                            <button type="submit" style="align-self: flex-end;">
                                <i class="fas fa-paper-plane"></i> Send
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        
        <aside>
            <div class="card fade-in">
                <h4><i class="fas fa-info-circle"></i> Conversation Info</h4>
                <p><strong>User:</strong> <?= esc($other_user['name']) ?></p>
                <p><strong>Type:</strong> <?= esc($other_user['type']) ?></p>
                <p><strong>Job:</strong> <?= esc($job['title']) ?></p>
                <p><strong>Messages:</strong> <?= count($messages) ?></p>
            </div>
        </aside>
    </div>
    
    <style>
        .message-bubble {
            max-width: 70%;
            margin-bottom: 15px;
            padding: 12px 16px;
            border-radius: 18px;
            position: relative;
            word-wrap: break-word;
        }
        
        .message-bubble.sent {
            background: var(--primary);
            color: white;
            margin-left: auto;
            border-bottom-right-radius: 4px;
        }
        
        .message-bubble.received {
            background: rgba(255, 255, 255, 0.1);
            color: var(--light);
            margin-right: auto;
            border-bottom-left-radius: 4px;
        }
        
        .message-content {
            display: flex;
            flex-direction: column;
        }
        
        .message-text {
            line-height: 1.4;
            margin-bottom: 5px;
        }
        
        .message-time {
            font-size: 0.75rem;
            opacity: 0.8;
            align-self: flex-end;
        }
        
        .message-form {
            margin-top: 20px;
        }
        
        .conversation-header {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px 20px;
            border-radius: var(--border-radius);
            margin-bottom: 20px;
        }
    </style>
    
    <script>
        // Auto-scroll to bottom of message thread
        document.addEventListener('DOMContentLoaded', function() {
            const messageThread = document.getElementById('messageThread');
            if(messageThread) {
                messageThread.scrollTop = messageThread.scrollHeight;
            }
            
            // Auto-focus message input
            const messageInput = document.querySelector('textarea[name="message"]');
            if(messageInput) {
                messageInput.focus();
            }
        });
    </script>
    <?php
    render_footer();
    exit;
}

// ---------------------------
// Enhanced render_header function with notifications
// ---------------------------
function render_header($pdo) {
    $user = current_user($pdo);
    $unread_count = 0;
    $notifications = [];
    
    if ($user) {
        $unread_count = get_unread_message_count($pdo, $user['id']);
        $notifications = get_user_notifications($pdo, $user['id']);
    }
    
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>WorkHub</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            /* Enhanced CSS */
            :root {
                --primary: #4361ee;
                --primary-dark: #3a56d4;
                --secondary: #7209b7;
                --success: #4cc9f0;
                --danger: #f72585;
                --warning: #f8961e;
                --info: #4895ef;
                --light: #f8f9fa;
                --dark: #212529;
                --gray: #6c757d;
                --gray-light: #e9ecef;
                --border-radius: 12px;
                --box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                --transition: all 0.3s ease;
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: var(--light);
                line-height: 1.6;
                overflow-x: hidden;
                position: relative;
                min-height: 100vh;
            }

            /* Interactive Background */
            #interactive-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
                overflow: hidden;
            }

            .bg-particle {
                position: absolute;
                border-radius: 50%;
                background: rgba(67, 97, 238, 0.1);
                animation: float 15s infinite linear;
            }

            @keyframes float {
                0% {
                    transform: translateY(0) translateX(0) rotate(0deg);
                    opacity: 0.2;
                }
                33% {
                    transform: translateY(-30px) translateX(20px) rotate(120deg);
                    opacity: 0.5;
                }
                66% {
                    transform: translateY(20px) translateX(-20px) rotate(240deg);
                    opacity: 0.3;
                }
                100% {
                    transform: translateY(0) translateX(0) rotate(360deg);
                    opacity: 0.2;
                }
            }

            /* Container */
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            /* Header */
            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px 0;
                margin-bottom: 30px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }

            .logo {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .logo-icon {
                width: 40px;
                height: 40px;
                background: var(--primary);
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 20px;
            }

            .logo h1 {
                font-size: 24px;
                font-weight: 700;
                background: linear-gradient(90deg, var(--primary), var(--success));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }

            nav {
                display: flex;
                align-items: center;
                gap: 20px;
            }

            nav a {
                color: var(--light);
                text-decoration: none;
                font-weight: 500;
                padding: 8px 16px;
                border-radius: var(--border-radius);
                transition: var(--transition);
                display: flex;
                align-items: center;
                gap: 8px;
                position: relative;
            }

            nav a:hover {
                background: rgba(255, 255, 255, 0.1);
            }

            .user-profile {
                display: flex;
                align-items: center;
                gap: 12px;
                background: rgba(255, 255, 255, 0.1);
                padding: 8px 16px;
                border-radius: var(--border-radius);
            }

            .user-avatar {
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: var(--primary);
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                font-size: 18px;
            }

            .user-info {
                display: flex;
                flex-direction: column;
            }

            .user-name {
                font-weight: 600;
            }

            .user-details {
                font-size: 0.8rem;
                color: var(--gray-light);
            }

            /* Notification Badge */
            .notification-badge {
                background: var(--danger);
                color: white;
                border-radius: 50%;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 0.7rem;
                font-weight: bold;
                margin-left: 5px;
            }

            /* Notification Dropdown */
            .notification-dropdown {
                position: relative;
                display: inline-block;
            }

            .notification-content {
                display: none;
                position: absolute;
                right: 0;
                top: 100%;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                min-width: 350px;
                box-shadow: var(--box-shadow);
                border-radius: var(--border-radius);
                z-index: 1000;
                margin-top: 10px;
            }

            .notification-content.show {
                display: block;
                animation: fadeIn 0.3s ease;
            }

            .notification-header {
                padding: 15px;
                border-bottom: 1px solid var(--gray-light);
                color: var(--dark);
                font-weight: 600;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .notification-item {
                padding: 12px 15px;
                border-bottom: 1px solid var(--gray-light);
                color: var(--dark);
                text-decoration: none;
                display: block;
                transition: var(--transition);
                position: relative;
            }

            .notification-item:hover {
                background: var(--gray-light);
            }

            .notification-item:last-child {
                border-bottom: none;
            }

            .notification-message {
                font-size: 0.9rem;
                margin-bottom: 5px;
                padding-right: 20px;
            }

            .notification-time {
                font-size: 0.8rem;
                color: var(--gray);
            }

            .notification-mark-read {
                position: absolute;
                right: 10px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                color: var(--primary);
                cursor: pointer;
                padding: 5px;
                border-radius: 3px;
            }

            .notification-mark-read:hover {
                background: var(--gray-light);
            }

            .view-all-notifications {
                display: block;
                text-align: center;
                padding: 12px;
                background: var(--primary);
                color: white;
                text-decoration: none;
                border-radius: 0 0 var(--border-radius) var(--border-radius);
            }

            .view-all-notifications:hover {
                background: var(--primary-dark);
            }

            /* Flash Messages */
            .flash {
                padding: 16px;
                border-radius: var(--border-radius);
                margin-bottom: 20px;
                display: flex;
                align-items: center;
                gap: 12px;
                animation: slideIn 0.5s ease;
            }

            .flash.info {
                background: rgba(72, 149, 239, 0.2);
                border-left: 4px solid var(--info);
            }

            .flash.success {
                background: rgba(76, 201, 240, 0.2);
                border-left: 4px solid var(--success);
            }

            .flash.danger {
                background: rgba(247, 37, 133, 0.2);
                border-left: 4px solid var(--danger);
            }

            .flash.warning {
                background: rgba(248, 150, 30, 0.2);
                border-left: 4px solid var(--warning);
            }

            @keyframes slideIn {
                from {
                    transform: translateY(-20px);
                    opacity: 0;
                }
                to {
                    transform: translateY(0);
                    opacity: 1;
                }
            }

            /* Grid Layout */
            .grid {
                display: grid;
                grid-template-columns: 1fr 350px;
                gap: 30px;
            }

            .grid-2 {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
            }

            /* Cards */
            .card {
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(10px);
                border-radius: var(--border-radius);
                padding: 24px;
                box-shadow: var(--box-shadow);
                border: 1px solid rgba(255, 255, 255, 0.1);
                transition: var(--transition);
            }

            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2);
            }

            .card h3, .card h4 {
                margin-bottom: 16px;
                color: var(--light);
                display: flex;
                align-items: center;
                gap: 10px;
            }

            /* Forms */
            form {
                margin: 20px 0;
            }

            .form-group {
                margin-bottom: 20px;
            }

            label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
            }

            input, select, textarea {
                width: 100%;
                padding: 12px 16px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: var(--border-radius);
                background: rgba(255, 255, 255, 0.05);
                color: var(--light);
                font-size: 16px;
                transition: var(--transition);
            }

            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.3);
            }

            input::placeholder, textarea::placeholder {
                color: rgba(255, 255, 255, 0.5);
            }

            .checkbox-group {
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .checkbox-group input {
                width: auto;
            }

            /* Buttons */
            button, .btn {
                padding: 12px 24px;
                border-radius: var(--border-radius);
                border: none;
                background: var(--primary);
                color: white;
                font-weight: 600;
                cursor: pointer;
                transition: var(--transition);
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }

            button:hover, .btn:hover {
                background: var(--primary-dark);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(67, 97, 238, 0.4);
            }

            .btn-secondary {
                background: var(--gray);
            }

            .btn-secondary:hover {
                background: #5a6268;
            }

            .btn-success {
                background: var(--success);
            }

            .btn-success:hover {
                background: #3ab0d9;
            }

            .btn-danger {
                background: var(--danger);
            }

            .btn-danger:hover {
                background: #e1156d;
            }

            /* Tables */
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }

            th, td {
                padding: 12px 16px;
                text-align: left;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }

            th {
                font-weight: 600;
                color: var(--success);
            }

            tr:hover {
                background: rgba(255, 255, 255, 0.05);
            }

            /* Job Tags */
            .job-meta {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin: 16px 0;
            }

            .job-tag {
                background: rgba(67, 97, 238, 0.2);
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 500;
            }

            /* Progress Bar */
            .progress-bar {
                height: 8px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
                margin: 10px 0;
                overflow: hidden;
            }

            .progress {
                height: 100%;
                background: var(--primary);
                border-radius: 4px;
                transition: width 0.5s ease;
            }

            /* Responsive */
            @media (max-width: 992px) {
                .grid {
                    grid-template-columns: 1fr;
                }
                
                .grid-2 {
                    grid-template-columns: 1fr;
                }
                
                header {
                    flex-direction: column;
                    gap: 20px;
                }
                
                nav {
                    flex-wrap: wrap;
                    justify-content: center;
                }
                
                .notification-content {
                    position: fixed;
                    left: 50%;
                    transform: translateX(-50%);
                    width: 90%;
                    max-width: 400px;
                }
                
                .message-bubble {
                    max-width: 85%;
                }
            }

            /* Animations */
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            .fade-in {
                animation: fadeIn 0.5s ease;
            }

            /* Password Strength Indicator */
            .password-strength {
                height: 4px;
                border-radius: 2px;
                margin-top: 5px;
                transition: var(--transition);
            }

            .strength-0 { width: 20%; background: var(--danger); }
            .strength-1 { width: 40%; background: var(--danger); }
            .strength-2 { width: 60%; background: var(--warning); }
            .strength-3 { width: 80%; background: var(--info); }
            .strength-4 { width: 100%; background: var(--success); }

            /* Stats Cards */
            .stats-container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }

            .stat-card {
                background: rgba(255, 255, 255, 0.05);
                border-radius: var(--border-radius);
                padding: 20px;
                text-align: center;
                transition: var(--transition);
            }

            .stat-card:hover {
                transform: translateY(-5px);
                background: rgba(255, 255, 255, 0.08);
            }

            .stat-value {
                font-size: 2rem;
                font-weight: 700;
                margin: 10px 0;
                background: linear-gradient(90deg, var(--primary), var(--success));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }

            .stat-label {
                font-size: 0.9rem;
                color: var(--gray-light);
            }

            /* Feature Icons */
            .feature-icon {
                width: 48px;
                height: 48px;
                border-radius: 12px;
                background: rgba(67, 97, 238, 0.2);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 20px;
                color: var(--primary);
                margin-bottom: 16px;
            }

            /* Logo Positioning */
            .logo-img {
                height: 40px;
                width: auto;
                object-fit: contain;
            }
        </style>
    </head>
    <body>
        <!-- Interactive Background -->
        <div id="interactive-bg"></div>

        <div class="container">
            <header>
                <div class="logo">
                    <div class="logo-icon">
                        <i class="fas fa-briefcase"></i>
                    </div>
                    <h1>WorkHub</h1>
                </div>
                <nav>
                    <a href="?action=home"><i class="fas fa-home"></i> Home</a>
                    <?php if($user): ?>
                        <a href="?action=dashboard"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                        <a href="?action=profile"><i class="fas fa-user"></i> Profile</a>
                        <a href="?action=messages"><i class="fas fa-comments"></i> Messages
                            <?php if($unread_count > 0): ?>
                                <span class="notification-badge"><?= $unread_count ?></span>
                            <?php endif; ?>
                        </a>
                        
                        <!-- Notifications Dropdown -->
                        <div class="notification-dropdown">
                            <a href="#" id="notification-toggle">
                                <i class="fas fa-bell"></i> Notifications
                                <?php if($unread_count > 0): ?>
                                    <span class="notification-badge"><?= $unread_count ?></span>
                                <?php endif; ?>
                            </a>
                            <div class="notification-content" id="notification-dropdown">
                                <div class="notification-header">
                                    <span>Notifications</span>
                                    <?php if($unread_count > 0): ?>
                                        <a href="?action=view_notifications" style="font-size: 0.8rem; color: var(--primary);">Mark all as read</a>
                                    <?php endif; ?>
                                </div>
                                <?php if(!empty($notifications)): ?>
                                    <?php foreach($notifications as $notification): ?>
                                        <a href="?action=conversation&user_id=<?= $notification['sender_id'] ?>&job_id=<?= $notification['job_id'] ?>" class="notification-item">
                                            <div class="notification-message">
                                                <strong><?= esc($notification['sender_name']) ?></strong>: 
                                                <?= esc(substr($notification['message'], 0, 50)) ?>...
                                            </div>
                                            <div class="notification-time">
                                                <?= date('M j, g:i A', strtotime($notification['created_at'])) ?>
                                            </div>
                                            <button class="notification-mark-read" onclick="event.preventDefault(); markNotificationRead(<?= $notification['id'] ?>, this);">
                                                <i class="fas fa-check"></i>
                                            </button>
                                        </a>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <div class="notification-item">
                                        <div class="notification-message">No new notifications</div>
                                    </div>
                                <?php endif; ?>
                                <a href="?action=messages" class="view-all-notifications">View All Messages</a>
                            </div>
                        </div>
                        
                        <div class="user-profile">
                            <div class="user-avatar"><?= strtoupper(substr($user['username'] ?? $user['name'], 0, 1)) ?></div>
                            <div class="user-info">
                                <div class="user-name"><?=esc($user['name'])?></div>
                                <div class="user-details"><?=esc($user['type'])?></div>
                            </div>
                        </div>
                        <a href="?action=logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
                    <?php else: ?>
                        <a href="?action=home#auth"><i class="fas fa-sign-in-alt"></i> Login / Register</a>
                    <?php endif; ?>
                </nav>
            </header>
        <?php
        $f = get_flash(); 
        if($f): 
        ?>
            <div class="flash <?=esc($f['type'])?> fade-in">
                <i class="fas fa-<?= 
                    $f['type'] === 'success' ? 'check-circle' : 
                    ($f['type'] === 'danger' ? 'exclamation-circle' : 
                    ($f['type'] === 'warning' ? 'exclamation-triangle' : 'info-circle'))
                ?>"></i>
                <div><?=$f['msg']?></div>
            </div>
        <?php endif;
}

function render_footer(){
    ?>
        </div> <!-- container -->
        <script>
            // Interactive Background
            document.addEventListener('DOMContentLoaded', function() {
                const bg = document.getElementById('interactive-bg');
                const particleCount = 20;
                
                for (let i = 0; i < particleCount; i++) {
                    const particle = document.createElement('div');
                    particle.classList.add('bg-particle');
                    
                    // Random size between 50px and 200px
                    const size = Math.random() * 150 + 50;
                    particle.style.width = `${size}px`;
                    particle.style.height = `${size}px`;
                    
                    // Random position
                    particle.style.left = `${Math.random() * 100}%`;
                    particle.style.top = `${Math.random() * 100}%`;
                    
                    // Random animation duration and delay
                    const duration = Math.random() * 1000 + 600;
                    const delay = Math.random() * 500;
                    particle.style.animationDuration = `${duration}s`;
                    particle.style.animationDelay = `${delay}s`;
                    
                    bg.appendChild(particle);
                }
                
                // Mouse move effect
                document.addEventListener('mousemove', function(e) {
                    const particles = document.querySelectorAll('.bg-particle');
                    const mouseX = e.clientX / window.innerWidth;
                    const mouseY = e.clientY / window.innerHeight;
                    
                    particles.forEach(particle => {
                        const speedX = (mouseX - 0.5) * 10;
                        const speedY = (mouseY - 0.5) * 10;
                        
                        particle.style.transform += ` translate(${speedX}px, ${speedY}px)`;
                    });
                });

                // Notification dropdown toggle
                const notificationToggle = document.getElementById('notification-toggle');
                const notificationDropdown = document.getElementById('notification-dropdown');
                
                if (notificationToggle && notificationDropdown) {
                    notificationToggle.addEventListener('click', function(e) {
                        e.preventDefault();
                        notificationDropdown.classList.toggle('show');
                    });

                    // Close dropdown when clicking outside
                    document.addEventListener('click', function(e) {
                        if (!notificationToggle.contains(e.target) && !notificationDropdown.contains(e.target)) {
                            notificationDropdown.classList.remove('show');
                        }
                    });
                }
            });

            // Mark notification as read
            function markNotificationRead(messageId, button) {
                fetch(`?action=mark_notification_read&message_id=${messageId}&ajax=1`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            const notificationItem = button.closest('.notification-item');
                            notificationItem.style.opacity = '0.6';
                            button.innerHTML = '<i class="fas fa-check-double"></i>';
                            button.style.color = 'var(--success)';
                            
                            // Update notification badge
                            const badge = document.querySelector('.notification-badge');
                            if (badge) {
                                const currentCount = parseInt(badge.textContent);
                                if (currentCount > 1) {
                                    badge.textContent = currentCount - 1;
                                } else {
                                    badge.style.display = 'none';
                                }
                            }
                        }
                    })
                    .catch(error => console.error('Error:', error));
            }

            // Password strength indicator
            function checkPasswordStrength(password) {
                let strength = 0;
                if (password.length >= 8) strength++;
                if (/[A-Z]/.test(password)) strength++;
                if (/[a-z]/.test(password)) strength++;
                if (/[0-9]/.test(password)) strength++;
                if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;
                return strength;
            }
            
            function updatePasswordStrength() {
                const password = document.getElementById('password')?.value || '';
                const strength = checkPasswordStrength(password);
                const indicator = document.getElementById('password-strength');
                if (indicator) {
                    indicator.className = `password-strength strength-${strength}`;
                }
            }

            // small helper to confirm actions
            function confirmAndPost(msg, params) {
                if(!confirm(msg)) return;
                const form = document.createElement('form');
                form.method = 'POST';
                for(const k in params) {
                    const i = document.createElement('input'); 
                    i.type='hidden'; 
                    i.name=k; 
                    i.value=params[k]; 
                    form.appendChild(i);
                }
                document.body.appendChild(form);
                form.submit();
            }

            // Form validation enhancements
            function validateForm(form) {
                const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
                let valid = true;
                
                inputs.forEach(input => {
                    if (!input.value.trim()) {
                        input.style.borderColor = 'var(--danger)';
                        valid = false;
                    } else {
                        input.style.borderColor = 'rgba(255, 255, 255, 0.2)';
                    }
                });
                
                return valid;
            }

            // Add event listeners to forms
            document.addEventListener('DOMContentLoaded', function() {
                const forms = document.querySelectorAll('form');
                forms.forEach(form => {
                    form.addEventListener('submit', function(e) {
                        if (!validateForm(form)) {
                            e.preventDefault();
                            alert('Please fill in all required fields.');
                        }
                    });
                });
            });

            // Auto-check for new messages every 30 seconds
            setInterval(function() {
                // In a real application, this would make an AJAX call to check for new messages
                // For now, we'll just reload the notification badge if needed
                const badge = document.querySelector('.notification-badge');
                if (badge) {
                    // Simulate checking for new messages
                    fetch(window.location.href)
                        .then(response => response.text())
                        .then(html => {
                            // This is a simplified version - in a real app you'd have an API endpoint
                            console.log('Checking for new messages...');
                        });
                }
            }, 30000);
        </script>
    </body>
    </html>
    <?php
}

// ---------------------------
// PROFILE PAGE
// ---------------------------
if($action === 'profile') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    render_header($pdo);
    ?>
    <div class="grid">
        <div>
            <div class="card fade-in">
                <h3><i class="fas fa-user"></i> My Profile</h3>
                <form method="POST" action="?action=update_profile">
                    <div class="grid-2">
                        <div class="form-group">
                            <label>Full Name *</label>
                            <input type="text" name="name" value="<?=esc($user['name'])?>" required>
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" value="<?=esc($user['email'])?>" readonly style="background:rgba(255,255,255,0.1);">
                            <small>Email cannot be changed</small>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Phone</label>
                        <input type="tel" name="phone" value="<?=esc($user['phone'])?>">
                    </div>
                    
                    <div class="form-group">
                        <label>Address</label>
                        <input type="text" name="address" value="<?=esc($user['address'])?>">
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>City</label>
                            <input type="text" name="city" value="<?=esc($user['city'])?>">
                        </div>
                        <div class="form-group">
                            <label>State</label>
                            <input type="text" name="state" value="<?=esc($user['state'])?>">
                        </div>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>Country</label>
                            <input type="text" name="country" value="<?=esc($user['country'])?>">
                        </div>
                        <div class="form-group">
                            <label>Postal Code</label>
                            <input type="text" name="postal_code" value="<?=esc($user['postal_code'])?>">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Bio</label>
                        <textarea name="bio" rows="4"><?=esc($user['bio'])?></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Skills</label>
                        <textarea name="skills" rows="3" placeholder="List your skills separated by commas"><?=esc($user['skills'])?></textarea>
                    </div>
                    
                    <button type="submit"><i class="fas fa-save"></i> Update Profile</button>
                </form>
            </div>
        </div>
        
        <aside>
            <div class="card fade-in">
                <h4><i class="fas fa-info-circle"></i> Profile Info</h4>
                <p><strong>Username:</strong> <?=esc($user['username'])?></p>
                <p><strong>Account Type:</strong> <?=esc($user['type'])?></p>
                <p><strong>Member Since:</strong> <?=date('M j, Y', strtotime($user['created_at']))?></p>
            </div>
            
            <div class="card fade-in">
                <h4><i class="fas fa-shield-alt"></i> Account Security</h4>
                <p>For security reasons, email cannot be changed. Contact support if needed.</p>
                <a href="?action=dashboard" class="btn-secondary" style="width: 100%; margin-top: 10px;">
                    <i class="fas fa-tachometer-alt"></i> Back to Dashboard
                </a>
            </div>
        </aside>
    </div>
    <?php
    render_footer();
    exit;
}

// ---------------------------
// JOB DETAILS PAGE
// ---------------------------
if($action === 'job') {
    $job_id = intval($_GET['id'] ?? 0);
    if(!$job_id) { flash("Job not found.", 'danger'); header("Location: ?action=home"); exit; }
    
    $stmt = $pdo->prepare("SELECT j.*, u.name as employer_name FROM jobs j JOIN users u ON j.employer_id=u.id WHERE j.id=?");
    $stmt->execute([$job_id]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);
    if(!$job) { flash("Job not found.", 'danger'); header("Location: ?action=home"); exit; }
    
    render_header($pdo);
    ?>
    <div class="grid">
        <div>
            <div class="card fade-in">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                    <div>
                        <h3 style="margin: 0;"><?=esc($job['title'])?></h3>
                        <p style="margin: 5px 0 0 0; color: var(--success);">
                            <i class="fas fa-user-tie"></i> Posted by <?=esc($job['employer_name'])?>
                        </p>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 1.5rem; font-weight: bold; color: var(--success);">$<?=number_format($job['budget'], 2)?></div>
                        <div style="font-size: 0.9rem; color: var(--gray-light);">Budget</div>
                    </div>
                </div>
                
                <div class="job-meta">
                    <span class="job-tag"><i class="fas fa-tag"></i> <?=esc($job['category'])?></span>
                    <span class="job-tag"><i class="fas fa-clock"></i> <?=esc($job['job_type'])?></span>
                    <span class="job-tag"><i class="fas fa-signal"></i> <?=esc($job['experience_level'])?></span>
                    <?php if($job['remote_ok']): ?>
                        <span class="job-tag"><i class="fas fa-wifi"></i> Remote OK</span>
                    <?php endif; ?>
                </div>
                
                <div style="margin: 20px 0;">
                    <h4>Job Description</h4>
                    <p style="white-space: pre-line;"><?=esc($job['description'])?></p>
                </div>
                
                <?php if($job['skills_required']): ?>
                <div style="margin: 20px 0;">
                    <h4>Skills Required</h4>
                    <p><?=esc($job['skills_required'])?></p>
                </div>
                <?php endif; ?>
                
                <?php if($job['duration']): ?>
                <div style="margin: 20px 0;">
                    <h4>Estimated Duration</h4>
                    <p><?=esc($job['duration'])?></p>
                </div>
                <?php endif; ?>
                
                <?php if($job['job_address'] || $job['job_city'] || $job['job_state']): ?>
                <div style="margin: 20px 0;">
                    <h4>Location</h4>
                    <p>
                        <?php if($job['job_address']): ?><?=esc($job['job_address'])?>, <?php endif; ?>
                        <?php if($job['job_city']): ?><?=esc($job['job_city'])?>, <?php endif; ?>
                        <?php if($job['job_state']): ?><?=esc($job['job_state'])?><?php endif; ?>
                        <?php if($job['job_country']): ?>, <?=esc($job['job_country'])?><?php endif; ?>
                    </p>
                </div>
                <?php endif; ?>
                
                <div style="margin: 20px 0; padding: 15px; background: rgba(255,255,255,0.05); border-radius: var(--border-radius);">
                    <h4 style="color: var(--success); margin-bottom: 10px;"><i class="fas fa-info-circle"></i> Job Status</h4>
                    <p><strong>Status:</strong> <span style="text-transform: capitalize;"><?=esc($job['status'])?></span></p>
                    <p><strong>Posted:</strong> <?=date('M j, Y', strtotime($job['created_at']))?></p>
                </div>
            </div>
            
            <?php if(is_logged_in()): ?>
            <?php $user = current_user($pdo); ?>
            <?php if($user['type'] === 'freelancer' && $job['status'] === 'open'): ?>
            <div class="card fade-in">
                <h4><i class="fas fa-paper-plane"></i> Apply for this Job</h4>
                <form method="POST" action="?action=apply">
                    <input type="hidden" name="job_id" value="<?=$job['id']?>">
                    
                    <div class="form-group">
                        <label>Your Proposal *</label>
                        <textarea name="proposal" rows="5" placeholder="Describe why you're the right fit for this job..." required></textarea>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>Your Bid ($) *</label>
                            <input type="number" name="bid" step="0.01" min="0.01" required>
                        </div>
                        <div class="form-group">
                            <label>Estimated Days *</label>
                            <input type="number" name="estimated_days" min="1" required>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn-success">
                        <i class="fas fa-paper-plane"></i> Submit Application
                    </button>
                </form>
            </div>
            <?php elseif($user['type'] === 'freelancer'): ?>
            <div class="card fade-in">
                <h4><i class="fas fa-info-circle"></i> Job Status</h4>
                <p>This job is no longer accepting applications.</p>
            </div>
            <?php endif; ?>
            <?php endif; ?>
        </div>
        
        <aside>
            <div class="card fade-in">
                <h4><i class="fas fa-briefcase"></i> Job Summary</h4>
                <p><strong>Category:</strong> <?=esc($job['category'])?></p>
                <p><strong>Type:</strong> <?=esc($job['job_type'])?></p>
                <p><strong>Experience:</strong> <?=esc($job['experience_level'])?></p>
                <p><strong>Budget:</strong> $<?=number_format($job['budget'], 2)?></p>
                <p><strong>Status:</strong> <span style="text-transform: capitalize;"><?=esc($job['status'])?></span></p>
                <?php if($job['remote_ok']): ?>
                    <p><strong>Remote:</strong> Yes</p>
                <?php endif; ?>
            </div>
            
            <div class="card fade-in">
                <h4><i class="fas fa-lightbulb"></i> Quick Actions</h4>
                <a href="?action=home" class="btn" style="width: 100%; margin-bottom: 10px;">
                    <i class="fas fa-search"></i> Browse More Jobs
                </a>
                <?php if(is_logged_in()): ?>
                <a href="?action=dashboard" class="btn-secondary" style="width: 100%;">
                    <i class="fas fa-tachometer-alt"></i> Back to Dashboard
                </a>
                <?php else: ?>
                <a href="?action=home#auth" class="btn-secondary" style="width: 100%;">
                    <i class="fas fa-sign-in-alt"></i> Login to Apply
                </a>
                <?php endif; ?>
            </div>
        </aside>
    </div>
    <?php
    render_footer();
    exit;
}

// ---------------------------
// DASHBOARD
// ---------------------------
if($action === 'dashboard') {
    if(!is_logged_in()) { flash("Login first.", 'danger'); header("Location: ?action=home"); exit; }
    $user = current_user($pdo);
    render_header($pdo);
    
    if($user['type'] === 'employer') {
        // Employer dashboard
        $jobs = $pdo->prepare("SELECT * FROM jobs WHERE employer_id=? ORDER BY created_at DESC");
        $jobs->execute([$user['id']]);
        $jobs = $jobs->fetchAll(PDO::FETCH_ASSOC);
        
        $applications = $pdo->prepare("
            SELECT a.*, j.title as job_title, u.name as freelancer_name, u.skills as freelancer_skills 
            FROM applications a 
            JOIN jobs j ON a.job_id=j.id 
            JOIN users u ON a.freelancer_id=u.id 
            WHERE j.employer_id=? 
            ORDER BY a.created_at DESC
        ");
        $applications->execute([$user['id']]);
        $applications = $applications->fetchAll(PDO::FETCH_ASSOC);
        ?>
        <div class="grid">
            <div>
                <div class="card fade-in">
                    <h3><i class="fas fa-tachometer-alt"></i> Employer Dashboard</h3>
                    <p>Welcome back, <?=esc($user['name'])?>! Here's an overview of your job postings and applications.</p>
                </div>
                
                <div class="card fade-in">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                        <h4 style="margin: 0;"><i class="fas fa-briefcase"></i> My Job Postings</h4>
                        <button onclick="document.getElementById('jobModal').style.display='block'" class="btn-success">
                            <i class="fas fa-plus"></i> Post New Job
                        </button>
                    </div>
                    
                    <?php if($jobs): ?>
                        <div style="overflow-x: auto;">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Title</th>
                                        <th>Budget</th>
                                        <th>Status</th>
                                        <th>Applications</th>
                                        <th>Posted</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach($jobs as $job): 
                                        $app_count = $pdo->prepare("SELECT COUNT(*) FROM applications WHERE job_id=?");
                                        $app_count->execute([$job['id']]);
                                        $app_count = $app_count->fetchColumn();
                                    ?>
                                    <tr>
                                        <td><a href="?action=job&id=<?=$job['id']?>" style="color: var(--light); text-decoration: none;"><?=esc($job['title'])?></a></td>
                                        <td>$<?=number_format($job['budget'], 2)?></td>
                                        <td>
                                            <span style="text-transform: capitalize; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; 
                                                background: <?= 
                                                    $job['status'] === 'open' ? 'var(--success)' : 
                                                    ($job['status'] === 'assigned' ? 'var(--info)' : 
                                                    ($job['status'] === 'completed' ? 'var(--primary)' : 'var(--gray)'))
                                                ?>;">
                                                <?=esc($job['status'])?>
                                            </span>
                                        </td>
                                        <td><?=$app_count?></td>
                                        <td><?=date('M j, Y', strtotime($job['created_at']))?></td>
                                        <td>
                                            <a href="?action=job&id=<?=$job['id']?>" class="btn" style="padding: 6px 12px; font-size: 0.8rem;">
                                                <i class="fas fa-eye"></i> View
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <p>You haven't posted any jobs yet. <a href="#" onclick="document.getElementById('jobModal').style.display='block'" style="color: var(--success);">Post your first job!</a></p>
                    <?php endif; ?>
                </div>
                
                <?php if($applications): ?>
                <div class="card fade-in">
                    <h4><i class="fas fa-users"></i> Recent Applications</h4>
                    <div style="overflow-x: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Job</th>
                                    <th>Freelancer</th>
                                    <th>Bid</th>
                                    <th>Status</th>
                                    <th>Applied</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach($applications as $app): ?>
                                <tr>
                                    <td><?=esc($app['job_title'])?></td>
                                    <td><?=esc($app['freelancer_name'])?></td>
                                    <td>$<?=number_format($app['bid'], 2)?></td>
                                    <td>
                                        <span style="text-transform: capitalize; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; 
                                            background: <?= 
                                                $app['status'] === 'pending' ? 'var(--warning)' : 
                                                ($app['status'] === 'accepted' ? 'var(--success)' : 'var(--danger)')
                                            ?>;">
                                            <?=esc($app['status'])?>
                                        </span>
                                    </td>
                                    <td><?=date('M j, Y', strtotime($app['created_at']))?></td>
                                    <td>
                                        <?php if($app['status'] === 'pending'): ?>
                                        <form method="POST" action="?action=accept_application" style="display: inline;">
                                            <input type="hidden" name="app_id" value="<?=$app['id']?>">
                                            <button type="submit" class="btn-success" style="padding: 6px 12px; font-size: 0.8rem;">
                                                <i class="fas fa-check"></i> Accept
                                            </button>
                                        </form>
                                        <?php endif; ?>
                                        <a href="?action=job&id=<?=$app['job_id']?>" class="btn" style="padding: 6px 12px; font-size: 0.8rem;">
                                            <i class="fas fa-eye"></i> View
                                        </a>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            
            <aside>
                <div class="card fade-in">
                    <h4><i class="fas fa-chart-bar"></i> Quick Stats</h4>
                    <?php
                    $total_jobs = count($jobs);
                    $open_jobs = array_filter($jobs, fn($j) => $j['status'] === 'open');
                    $completed_jobs = array_filter($jobs, fn($j) => $j['status'] === 'completed');
                    $total_apps = count($applications);
                    $pending_apps = array_filter($applications, fn($a) => $a['status'] === 'pending');
                    ?>
                    <div class="stats-container">
                        <div class="stat-card">
                            <div class="stat-value"><?=$total_jobs?></div>
                            <div class="stat-label">Total Jobs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?=count($open_jobs)?></div>
                            <div class="stat-label">Open Jobs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?=$total_apps?></div>
                            <div class="stat-label">Applications</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?=count($pending_apps)?></div>
                            <div class="stat-label">Pending</div>
                        </div>
                    </div>
                </div>
                
                <div class="card fade-in">
                    <h4><i class="fas fa-rocket"></i> Quick Actions</h4>
                    <a href="?action=home" class="btn" style="width: 100%; margin-bottom: 10px;">
                        <i class="fas fa-search"></i> Browse Freelancers
                    </a>
                    <a href="?action=profile" class="btn-secondary" style="width: 100%; margin-bottom: 10px;">
                        <i class="fas fa-user"></i> Update Profile
                    </a>
                    <a href="?action=messages" class="btn-secondary" style="width: 100%;">
                        <i class="fas fa-comments"></i> View Messages
                    </a>
                </div>
            </aside>
        </div>
        
        <!-- Job Posting Modal -->
        <div id="jobModal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5);">
            <div style="background: var(--dark); margin: 5% auto; padding: 20px; border-radius: var(--border-radius); width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h3 style="margin: 0;"><i class="fas fa-briefcase"></i> Post New Job</h3>
                    <button onclick="document.getElementById('jobModal').style.display='none'" style="background: none; border: none; color: var(--light); font-size: 1.5rem; cursor: pointer;">&times;</button>
                </div>
                
                <form method="POST" action="?action=post_job">
                    <div class="form-group">
                        <label>Job Title *</label>
                        <input type="text" name="title" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Job Description *</label>
                        <textarea name="description" rows="5" required></textarea>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>Budget ($) *</label>
                            <input type="number" name="budget" step="0.01" min="0.01" required>
                        </div>
                        <div class="form-group">
                            <label>Job Type *</label>
                            <select name="job_type" required>
                                <option value="one-time">One-time Project</option>
                                <option value="ongoing">Ongoing Work</option>
                                <option value="hourly">Hourly</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>Category *</label>
                            <input type="text" name="category" required>
                        </div>
                        <div class="form-group">
                            <label>Experience Level *</label>
                            <select name="experience_level" required>
                                <option value="entry">Entry Level</option>
                                <option value="intermediate">Intermediate</option>
                                <option value="expert">Expert</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Skills Required</label>
                        <textarea name="skills_required" rows="3" placeholder="List required skills separated by commas"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Estimated Duration</label>
                        <input type="text" name="duration" placeholder="e.g., 2 weeks, 1 month">
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>Address</label>
                            <input type="text" name="job_address">
                        </div>
                        <div class="form-group">
                            <label>City</label>
                            <input type="text" name="job_city">
                        </div>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label>State</label>
                            <input type="text" name="job_state">
                        </div>
                        <div class="form-group">
                            <label>Country</label>
                            <input type="text" name="job_country">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" name="remote_ok" value="1">
                            <span>Remote work is acceptable</span>
                        </label>
                    </div>
                    
                    <div style="display: flex; gap: 10px;">
                        <button type="submit" class="btn-success">
                            <i class="fas fa-paper-plane"></i> Post Job
                        </button>
                        <button type="button" onclick="document.getElementById('jobModal').style.display='none'" class="btn-secondary">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            // Close modal when clicking outside
            window.onclick = function(event) {
                const modal = document.getElementById('jobModal');
                if (event.target === modal) {
                    modal.style.display = "none";
                }
            }
        </script>
        <?php
    } else {
        // Freelancer dashboard
        $applications = $pdo->prepare("
            SELECT a.*, j.title as job_title, j.budget as job_budget, j.status as job_status, u.name as employer_name 
            FROM applications a 
            JOIN jobs j ON a.job_id=j.id 
            JOIN users u ON j.employer_id=u.id 
            WHERE a.freelancer_id=? 
            ORDER BY a.created_at DESC
        ");
        $applications->execute([$user['id']]);
        $applications = $applications->fetchAll(PDO::FETCH_ASSOC);
        
        $available_jobs = $pdo->prepare("
            SELECT j.*, u.name as employer_name 
            FROM jobs j 
            JOIN users u ON j.employer_id=u.id 
            WHERE j.status='open' 
            ORDER BY j.created_at DESC 
            LIMIT 5
        ");
        $available_jobs->execute();
        $available_jobs = $available_jobs->fetchAll(PDO::FETCH_ASSOC);
        ?>
        <div class="grid">
            <div>
                <div class="card fade-in">
                    <h3><i class="fas fa-tachometer-alt"></i> Freelancer Dashboard</h3>
                    <p>Welcome back, <?=esc($user['name'])?>! Here's an overview of your applications and available jobs.</p>
                </div>
                
                <div class="card fade-in">
                    <h4><i class="fas fa-paper-plane"></i> My Applications</h4>
                    <?php if($applications): ?>
                        <div style="overflow-x: auto;">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Job</th>
                                        <th>Employer</th>
                                        <th>My Bid</th>
                                        <th>Status</th>
                                        <th>Applied</th>
                                        <th>Job Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach($applications as $app): ?>
                                    <tr>
                                        <td><a href="?action=job&id=<?=$app['job_id']?>" style="color: var(--light); text-decoration: none;"><?=esc($app['job_title'])?></a></td>
                                        <td><?=esc($app['employer_name'])?></td>
                                        <td>$<?=number_format($app['bid'], 2)?></td>
                                        <td>
                                            <span style="text-transform: capitalize; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; 
                                                background: <?= 
                                                    $app['status'] === 'pending' ? 'var(--warning)' : 
                                                    ($app['status'] === 'accepted' ? 'var(--success)' : 'var(--danger)')
                                                ?>;">
                                                <?=esc($app['status'])?>
                                            </span>
                                        </td>
                                        <td><?=date('M j, Y', strtotime($app['created_at']))?></td>
                                        <td>
                                            <span style="text-transform: capitalize; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; 
                                                background: <?= 
                                                    $app['job_status'] === 'open' ? 'var(--success)' : 
                                                    ($app['job_status'] === 'assigned' ? 'var(--info)' : 
                                                    ($app['job_status'] === 'completed' ? 'var(--primary)' : 'var(--gray)'))
                                                ?>;">
                                                <?=esc($app['job_status'])?>
                                            </span>
                                        </td>
                                        <td>
                                            <a href="?action=job&id=<?=$app['job_id']?>" class="btn" style="padding: 6px 12px; font-size: 0.8rem;">
                                                <i class="fas fa-eye"></i> View
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <p>You haven't applied to any jobs yet. <a href="?action=home" style="color: var(--success);">Browse available jobs!</a></p>
                    <?php endif; ?>
                </div>
                
                <div class="card fade-in">
                    <h4><i class="fas fa-briefcase"></i> Available Jobs</h4>
                    <?php if($available_jobs): ?>
                        <div style="overflow-x: auto;">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Title</th>
                                        <th>Employer</th>
                                        <th>Budget</th>
                                        <th>Category</th>
                                        <th>Posted</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach($available_jobs as $job): ?>
                                    <tr>
                                        <td><a href="?action=job&id=<?=$job['id']?>" style="color: var(--light); text-decoration: none;"><?=esc($job['title'])?></a></td>
                                        <td><?=esc($job['employer_name'])?></td>
                                        <td>$<?=number_format($job['budget'], 2)?></td>
                                        <td><?=esc($job['category'])?></td>
                                        <td><?=date('M j, Y', strtotime($job['created_at']))?></td>
                                        <td>
                                            <a href="?action=job&id=<?=$job['id']?>" class="btn" style="padding: 6px 12px; font-size: 0.8rem;">
                                                <i class="fas fa-eye"></i> View
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <div style="text-align: center; margin-top: 15px;">
                            <a href="?action=home" class="btn-secondary">
                                <i class="fas fa-search"></i> Browse All Jobs
                            </a>
                        </div>
                    <?php else: ?>
                        <p>No available jobs at the moment. Check back later!</p>
                    <?php endif; ?>
                </div>
            </div>
            
            <aside>
                <div class="card fade-in">
                    <h4><i class="fas fa-chart-bar"></i> Application Stats</h4>
                    <?php
                    $total_apps = count($applications);
                    $pending_apps = array_filter($applications, fn($a) => $a['status'] === 'pending');
                    $accepted_apps = array_filter($applications, fn($a) => $a['status'] === 'accepted');
                    $rejected_apps = array_filter($applications, fn($a) => $a['status'] === 'rejected');
                    ?>
                    <div class="stats-container">
                        <div class="stat-card">
                            <div class="stat-value"><?=$total_apps?></div>
                            <div class="stat-label">Total Apps</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?=count($pending_apps)?></div>
                            <div class="stat-label">Pending</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?=count($accepted_apps)?></div>
                            <div class="stat-label">Accepted</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?=count($rejected_apps)?></div>
                            <div class="stat-label">Rejected</div>
                        </div>
                    </div>
                </div>
                
                <div class="card fade-in">
                    <h4><i class="fas fa-rocket"></i> Quick Actions</h4>
                    <a href="?action=home" class="btn" style="width: 100%; margin-bottom: 10px;">
                        <i class="fas fa-search"></i> Browse Jobs
                    </a>
                    <a href="?action=profile" class="btn-secondary" style="width: 100%; margin-bottom: 10px;">
                        <i class="fas fa-user"></i> Update Profile
                    </a>
                    <a href="?action=messages" class="btn-secondary" style="width: 100%;">
                        <i class="fas fa-comments"></i> View Messages
                    </a>
                </div>
            </aside>
        </div>
        <?php
    }
    render_footer();
    exit;
}

// ---------------------------
// HOME PAGE (default)
// ---------------------------
render_header($pdo);
?>
<div class="grid">
    <div>
        <div class="card fade-in">
            <h1 style="font-size: 2.5rem; margin-bottom: 10px; background: linear-gradient(90deg, var(--primary), var(--success)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                Welcome to WorkHub
            </h1>
            <p style="font-size: 1.2rem; color: var(--gray-light); margin-bottom: 30px;">
                Connect with talented freelancers or find your next project opportunity
            </p>
            
            <div class="stats-container">
                <div class="stat-card">
                    <div class="feature-icon">
                        <i class="fas fa-briefcase"></i>
                    </div>
                    <div class="stat-value">
                        <?php
                        $job_count = $pdo->query("SELECT COUNT(*) FROM jobs WHERE status='open'")->fetchColumn();
                        echo $job_count;
                        ?>
                    </div>
                    <div class="stat-label">Open Jobs</div>
                </div>
                <div class="stat-card">
                    <div class="feature-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-value">
                        <?php
                        $user_count = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
                        echo $user_count;
                        ?>
                    </div>
                    <div class="stat-label">Registered Users</div>
                </div>
                <div class="stat-card">
                    <div class="feature-icon">
                        <i class="fas fa-handshake"></i>
                    </div>
                    <div class="stat-value">
                        <?php
                        $completed_count = $pdo->query("SELECT COUNT(*) FROM jobs WHERE status='completed'")->fetchColumn();
                        echo $completed_count;
                        ?>
                    </div>
                    <div class="stat-label">Completed Jobs</div>
                </div>
                <div class="stat-card">
                    <div class="feature-icon">
                        <i class="fas fa-star"></i>
                    </div>
                    <div class="stat-value">100%</div>
                    <div class="stat-label">Satisfaction</div>
                </div>
            </div>
        </div>
        
        <div class="card fade-in">
            <h3><i class="fas fa-fire"></i> Featured Jobs</h3>
            <?php
            $featured_jobs = $pdo->query("
                SELECT j.*, u.name as employer_name 
                FROM jobs j 
                JOIN users u ON j.employer_id=u.id 
                WHERE j.status='open' 
                ORDER BY j.created_at DESC 
                LIMIT 6
            ")->fetchAll(PDO::FETCH_ASSOC);
            
            if($featured_jobs): 
            ?>
                <div class="grid-2">
                    <?php foreach($featured_jobs as $job): ?>
                    <div class="card" style="background: rgba(255,255,255,0.03);">
                        <h4 style="margin-bottom: 10px;">
                            <a href="?action=job&id=<?=$job['id']?>" style="color: var(--light); text-decoration: none;">
                                <?=esc($job['title'])?>
                            </a>
                        </h4>
                        <p style="color: var(--success); font-size: 1.1rem; font-weight: bold; margin-bottom: 10px;">
                            $<?=number_format($job['budget'], 2)?>
                        </p>
                        <div class="job-meta">
                            <span class="job-tag"><?=esc($job['category'])?></span>
                            <span class="job-tag"><?=esc($job['job_type'])?></span>
                        </div>
                        <p style="margin: 10px 0; font-size: 0.9rem; color: var(--gray-light);">
                            <i class="fas fa-user-tie"></i> <?=esc($job['employer_name'])?>
                        </p>
                        <p style="font-size: 0.9rem; color: var(--gray-light); margin-bottom: 15px;">
                            <?=esc(substr($job['description'], 0, 100))?>...
                        </p>
                        <a href="?action=job&id=<?=$job['id']?>" class="btn" style="width: 100%;">
                            <i class="fas fa-eye"></i> View Job
                        </a>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="?action=dashboard" class="btn-secondary">
                        <i class="fas fa-search"></i> Browse All Jobs
                    </a>
                </div>
            <?php else: ?>
                <p>No featured jobs available at the moment. Check back later!</p>
            <?php endif; ?>
        </div>
    </div>
    
    <aside>
        <div class="card fade-in" id="auth">
            <h3><i class="fas fa-user-plus"></i> Join WorkHub</h3>
            <?php if(!is_logged_in()): ?>
                <ul style="margin-bottom: 20px; padding-left: 20px;">
                    <li>Find quality freelancers</li>
                    <li>Get your projects done</li>
                    <li>Secure payment system</li>
                    <li>24/7 support</li>
                </ul>
                
                <!-- Registration Form -->
                <form method="POST" action="?action=register" style="margin-top: 20px;">
                    <div class="form-group">
                        <label>Username *</label>
                        <input type="text" name="username" value="<?=esc($_SESSION['form_data']['username'] ?? '')?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Full Name *</label>
                        <input type="text" name="name" value="<?=esc($_SESSION['form_data']['name'] ?? '')?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Email *</label>
                        <input type="email" name="email" value="<?=esc($_SESSION['form_data']['email'] ?? '')?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Phone</label>
                        <input type="tel" name="phone" value="<?=esc($_SESSION['form_data']['phone'] ?? '')?>">
                    </div>
                    
                    <div class="form-group">
                        <label>Account Type *</label>
                        <select name="type" required>
                            <option value="freelancer" <?=($_SESSION['form_data']['type'] ?? '') === 'freelancer' ? 'selected' : ''?>>Freelancer</option>
                            <option value="employer" <?=($_SESSION['form_data']['type'] ?? '') === 'employer' ? 'selected' : ''?>>Employer</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>Password *</label>
                        <input type="password" name="password" id="password" oninput="updatePasswordStrength()" required>
                        <div id="password-strength" class="password-strength strength-0"></div>
                    </div>
                    
                    <div class="form-group">
                        <label>Confirm Password *</label>
                        <input type="password" name="confirm_password" required>
                    </div>
                    
                    <button type="submit" class="btn-success" style="width: 100%;">
                        <i class="fas fa-user-plus"></i> Register
                    </button>
                </form>
                
                <hr style="margin: 20px 0; border-color: rgba(255,255,255,0.1);">
                
                <!-- Login Form -->
                <h4 style="margin-bottom: 15px;"><i class="fas fa-sign-in-alt"></i> Existing User?</h4>
                <form method="POST" action="?action=login">
                    <div class="form-group">
                        <label>Username or Email</label>
                        <input type="text" name="login" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="btn" style="width: 100%;">
                        <i class="fas fa-sign-in-alt"></i> Login
                    </button>
                </form>
            <?php else: ?>
                <div style="text-align: center; padding: 20px;">
                    <div class="user-avatar" style="margin: 0 auto 15px; width: 60px; height: 60px; font-size: 24px;">
                        <?php $user = current_user($pdo); echo strtoupper(substr($user['username'], 0, 1)); ?>
                    </div>
                    <h4>Welcome back, <?=esc($user['name'])?>!</h4>
                    <p>You're logged in as <?=esc($user['type'])?></p>
                    <a href="?action=dashboard" class="btn" style="width: 100%; margin-bottom: 10px;">
                        <i class="fas fa-tachometer-alt"></i> Go to Dashboard
                    </a>
                    <a href="?action=profile" class="btn-secondary" style="width: 100%;">
                        <i class="fas fa-user"></i> My Profile
                    </a>
                </div>
            <?php endif; ?>
        </div>
        
        <div class="card fade-in">
            <h4><i class="fas fa-info-circle"></i> How It Works</h4>
            <div style="margin: 15px 0;">
                <div style="display: flex; align-items: center; margin-bottom: 15px;">
                    <div style="background: var(--primary); color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 10px;">1</div>
                    <span>Create your account</span>
                </div>
                <div style="display: flex; align-items: center; margin-bottom: 15px;">
                    <div style="background: var(--primary); color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 10px;">2</div>
                    <span>Post jobs or apply</span>
                </div>
                <div style="display: flex; align-items: center; margin-bottom: 15px;">
                    <div style="background: var(--primary); color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 10px;">3</div>
                    <span>Connect and communicate</span>
                </div>
                <div style="display: flex; align-items: center;">
                    <div style="background: var(--primary); color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 10px;">4</div>
                    <span>Get work done</span>
                </div>
            </div>
        </div>
    </aside>
</div>

<script>
    // Initialize password strength indicator
    document.addEventListener('DOMContentLoaded', function() {
        updatePasswordStrength();
    });
</script>

<?php
render_footer();
?>