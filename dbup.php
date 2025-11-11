<?php
// database_fix_and_setup.php
session_start();
$db_host = '127.0.0.1';
$db_name = 'job_commission';
$db_user = 'root';
$db_pass = '';

try {
    $pdo = new PDO("mysql:host={$db_host};dbname={$db_name};charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
} catch (Exception $e) {
    die("Database connection failed: " . htmlspecialchars($e->getMessage()));
}

function executeMigration($pdo, $sql, $description) {
    try {
        $pdo->exec($sql);
        echo "✅ $description - SUCCESS<br>";
        return true;
    } catch (Exception $e) {
        echo "❌ $description - FAILED: " . $e->getMessage() . "<br>";
        return false;
    }
}

echo "<h2>Database Fix and Setup Started</h2>";

// Step 1: Emergency Fix - Check and fix messages table
echo "<h3>Step 1: Checking Messages Table</h3>";

try {
    // Check if messages table exists
    $tableExists = $pdo->query("SHOW TABLES LIKE 'messages'")->fetchColumn();
    
    if ($tableExists) {
        echo "✅ Messages table exists<br>";
        
        // Check if read_status column exists
        $columnExists = $pdo->query("SHOW COLUMNS FROM messages LIKE 'read_status'")->fetchColumn();
        
        if (!$columnExists) {
            echo "❌ read_status column missing - adding it now...<br>";
            $pdo->exec("ALTER TABLE messages ADD COLUMN read_status TINYINT(1) DEFAULT 0");
            echo "✅ read_status column added successfully!<br>";
        } else {
            echo "✅ read_status column already exists<br>";
        }
        
        // Check for other required columns in messages table
        $requiredColumns = ['sender_id', 'receiver_id', 'job_id', 'message', 'parent_message_id', 'created_at'];
        foreach ($requiredColumns as $column) {
            $colExists = $pdo->query("SHOW COLUMNS FROM messages LIKE '$column'")->fetchColumn();
            if (!$colExists) {
                echo "❌ Column '$column' missing in messages table<br>";
            }
        }
        
    } else {
        echo "❌ Messages table doesn't exist - creating it...<br>";
        executeMigration($pdo, 
            "CREATE TABLE messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NOT NULL,
                receiver_id INT NOT NULL,
                job_id INT NOT NULL,
                message TEXT NOT NULL,
                parent_message_id INT DEFAULT NULL,
                read_status TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )", 
            "Create messages table"
        );
    }
} catch (Exception $e) {
    echo "❌ Messages table check failed: " . $e->getMessage() . "<br>";
}

// Step 2: Check and fix other tables
echo "<h3>Step 2: Checking Other Tables</h3>";

// Check and create users table if needed
$usersTableExists = $pdo->query("SHOW TABLES LIKE 'users'")->fetchColumn();
if (!$usersTableExists) {
    executeMigration($pdo, 
        "CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            phone VARCHAR(20),
            address TEXT,
            city VARCHAR(100),
            state VARCHAR(100),
            country VARCHAR(100),
            postal_code VARCHAR(20),
            bio TEXT,
            skills TEXT,
            profile_picture VARCHAR(255),
            password VARCHAR(255) NOT NULL,
            type ENUM('employer', 'freelancer') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )", 
        "Create users table"
    );
} else {
    echo "✅ Users table exists<br>";
    
    // Add missing columns to users table
    $userColumns = [
        'username' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(50) UNIQUE AFTER id",
        'phone' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(20) AFTER email",
        'address' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT AFTER phone",
        'city' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS city VARCHAR(100) AFTER address",
        'state' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS state VARCHAR(100) AFTER city",
        'country' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS country VARCHAR(100) AFTER state",
        'postal_code' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS postal_code VARCHAR(20) AFTER country",
        'bio' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT AFTER postal_code",
        'skills' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS skills TEXT AFTER bio",
        'profile_picture' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture VARCHAR(255) AFTER skills",
        'created_at' => "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    ];

    foreach ($userColumns as $column => $sql) {
        try {
            $pdo->exec($sql);
            echo "✅ Added $column to users table<br>";
        } catch (Exception $e) {
            echo "❌ Failed to add $column: " . $e->getMessage() . "<br>";
        }
    }
}

// Check and create jobs table if needed
$jobsTableExists = $pdo->query("SHOW TABLES LIKE 'jobs'")->fetchColumn();
if (!$jobsTableExists) {
    executeMigration($pdo, 
        "CREATE TABLE jobs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employer_id INT NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            budget DECIMAL(10,2) NOT NULL,
            job_type VARCHAR(20) DEFAULT 'one-time',
            category VARCHAR(100),
            skills_required TEXT,
            experience_level VARCHAR(20) DEFAULT 'intermediate',
            duration VARCHAR(50),
            job_address TEXT,
            job_city VARCHAR(100),
            job_state VARCHAR(100),
            job_country VARCHAR(100),
            remote_ok TINYINT(1) DEFAULT 0,
            status ENUM('open', 'assigned', 'in_progress', 'completed', 'cancelled') DEFAULT 'open',
            assigned_application_id INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
        )", 
        "Create jobs table"
    );
} else {
    echo "✅ Jobs table exists<br>";
    
    // Add missing columns to jobs table
    $jobColumns = [
        'job_type' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS job_type VARCHAR(20) DEFAULT 'one-time' AFTER budget",
        'category' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS category VARCHAR(100) AFTER job_type",
        'skills_required' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS skills_required TEXT AFTER category",
        'experience_level' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS experience_level VARCHAR(20) DEFAULT 'intermediate' AFTER skills_required",
        'duration' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS duration VARCHAR(50) AFTER experience_level",
        'job_address' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS job_address TEXT AFTER duration",
        'job_city' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS job_city VARCHAR(100) AFTER job_address",
        'job_state' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS job_state VARCHAR(100) AFTER job_city",
        'job_country' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS job_country VARCHAR(100) AFTER job_state",
        'remote_ok' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS remote_ok TINYINT(1) DEFAULT 0 AFTER job_country",
        'assigned_application_id' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS assigned_application_id INT DEFAULT NULL",
        'created_at' => "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    ];

    foreach ($jobColumns as $column => $sql) {
        try {
            $pdo->exec($sql);
            echo "✅ Added $column to jobs table<br>";
        } catch (Exception $e) {
            echo "❌ Failed to add $column: " . $e->getMessage() . "<br>";
        }
    }
}

// Check and create applications table if needed
$applicationsTableExists = $pdo->query("SHOW TABLES LIKE 'applications'")->fetchColumn();
if (!$applicationsTableExists) {
    executeMigration($pdo, 
        "CREATE TABLE applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            job_id INT NOT NULL,
            freelancer_id INT NOT NULL,
            proposal TEXT NOT NULL,
            bid DECIMAL(10,2) NOT NULL,
            estimated_days INT,
            status ENUM('pending', 'accepted', 'rejected', 'completed') DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
            FOREIGN KEY (freelancer_id) REFERENCES users(id) ON DELETE CASCADE
        )", 
        "Create applications table"
    );
} else {
    echo "✅ Applications table exists<br>";
    
    // Add estimated_days if missing
    try {
        $pdo->exec("ALTER TABLE applications ADD COLUMN IF NOT EXISTS estimated_days INT AFTER bid");
        echo "✅ Added estimated_days to applications table<br>";
    } catch (Exception $e) {
        echo "❌ Failed to add estimated_days: " . $e->getMessage() . "<br>";
    }
}

// Step 3: Set default usernames for existing users
echo "<h3>Step 3: Setting Default Usernames</h3>";
try {
    $pdo->exec("UPDATE users SET username = CONCAT('user', id) WHERE username IS NULL OR username = ''");
    echo "✅ Set default usernames for existing users - SUCCESS<br>";
} catch (Exception $e) {
    echo "❌ Set default usernames - FAILED: " . $e->getMessage() . "<br>";
}

// Step 4: Add sample data if no users exist
echo "<h3>Step 4: Adding Sample Data</h3>";
try {
    $userCount = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    
    if ($userCount == 0) {
        // Sample employer
        $pdo->exec("INSERT INTO users (username, name, email, password, type, skills) VALUES 
            ('employer1', 'John Employer', 'employer@test.com', '" . password_hash('password123', PASSWORD_DEFAULT) . "', 'employer', 'Project Management')");
        
        // Sample freelancer
        $pdo->exec("INSERT INTO users (username, name, email, password, type, skills) VALUES 
            ('freelancer1', 'Jane Freelancer', 'freelancer@test.com', '" . password_hash('password123', PASSWORD_DEFAULT) . "', 'freelancer', 'PHP, JavaScript, HTML, CSS, MySQL')");
        
        echo "✅ Added sample users - SUCCESS<br>";
        
        // Get the employer ID
        $employerId = $pdo->lastInsertId() - 1;
        
        // Sample job
        $pdo->exec("INSERT INTO jobs (employer_id, title, description, budget, job_type, category, skills_required, experience_level, duration, remote_ok) VALUES 
            ($employerId, 'Website Development', 'Need a professional website built with PHP and MySQL', 1500.00, 'one-time', 'Web Development', 'PHP, MySQL, HTML, CSS', 'intermediate', '2 weeks', 1)");
        
        echo "✅ Added sample job - SUCCESS<br>";
    } else {
        echo "✅ Users already exist - skipping sample data<br>";
    }
} catch (Exception $e) {
    echo "❌ Add sample data - FAILED: " . $e->getMessage() . "<br>";
}

echo "<h2>✅ Database Fix and Setup Completed Successfully!</h2>";
echo "<p><strong>You can now login with:</strong></p>";
echo "<ul>";
echo "<li><strong>Employer:</strong> employer@test.com / password123</li>";
echo "<li><strong>Freelancer:</strong> freelancer@test.com / password123</li>";
echo "</ul>";
echo "<p><a href='?action=home' style='background: #4361ee; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;'>Go to Home Page and Login</a></p>";

// Optional: Delete this file after setup (uncomment the line below)
// unlink(__FILE__);
?>