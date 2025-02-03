<?php

$logFile = 'log.txt'; // Path to the log file in the same directory as index.php
$current_time = date('Y-m-d H:i:s');

// Open the log file in append mode
try {
    // Open the log file in append mode
    $fileHandle = fopen($logFile, 'a');
    if ($fileHandle === false) {
        throw new Exception("Unable to open log file for writing.");
    }
    
    fwrite($fileHandle, $logMessage);
    fclose($fileHandle);
} catch (Exception $e) {
    // Handle exception if the file couldn't be opened or written to
    echo "Error writing to log file: " . $e->getMessage();
}

try{
	if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
		$secure_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
		header("Location: $secure_url", true, 301);  // Permanent redirect
		exit();
	}
} catch (Exception $e) {
    // Handle potential exceptions during the redirection process
    echo "Error during HTTPS redirection: " . $e->getMessage();
}

try {
	header_remove("X-Powered-By");

	// Security Headers
	header('X-Content-Type-Options: nosniff');
	header('X-XSS-Protection: 1; mode=block');
	header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
	header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; frame-src 'none'; upgrade-insecure-requests;");

	// Cache Control Headers
	header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
	header('Pragma: no-cache');

	// Clickjacking Protection
	header('X-Frame-Options: SAMEORIGIN');

	// Cross-Domain Policy
	header('X-Permitted-Cross-Domain-Policies: none');

	// CORS Configuration: Restrict to specific trusted domains
	$allowed_origins = ['https://craftscripters.xyz/', 'https://another-trusted-domain.com']; // Example trusted domains

	if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $allowed_origins)) {
		header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
		header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
		header("Access-Control-Allow-Headers: Content-Type, Authorization");
		header("Access-Control-Allow-Credentials: true");
	}

	// For preflight requests (OPTIONS method)
	if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
		exit(0);  // Respond with a success status to preflight requests
	}
} catch (Exception $e) {
    // Handle any exception that occurs while setting headers
    echo "Error setting headers: " . $e->getMessage();
}

try{
	// Cookie and Session Security
	setcookie('name', 'value', [
		'expires' => time() + 3600, 
		'path' => '/', 
		'domain' => $_SERVER['HTTP_HOST'], 
		'secure' => true, 
		'httponly' => true, 
		'samesite' => 'Strict' 
	]);

	session_set_cookie_params([
		'secure' => true,  // Ensure the session cookie is only sent over HTTPS
		'httponly' => true, // Make session cookie inaccessible to JavaScript
		'samesite' => 'Strict' // Prevent cross-site requests
	]);
} catch (Exception $e) {
    // Handle any exception that occurs while setting cookies or session parameters
    echo "Error setting cookies or session parameters: " . $e->getMessage();
}

session_start();

try{
	// Initialize session on first load
	if (!isset($_SESSION['started'])) {
		session_regenerate_id(true);

		$_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
		$_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
		$_SESSION['started'] = true;
	}

	// Check IP address and user-agent for session hijacking protection
	if (isset($_SESSION['ip_address'], $_SESSION['user_agent'])) {
		if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
			session_unset();
			session_destroy();
			header("Location: index.php"); 
			exit();
		}

		if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
			session_unset();
			session_destroy();
			header("Location: index.php"); 
			exit();
		}
	}

	// Generate CSRF token if it doesn't exist
	if (!isset($_SESSION['csrf_token'])) {
		$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
	}

	$timeout_duration = 600; // 10 minutes
	if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout_duration) {
		session_unset();
		session_destroy();
		header("Location: index.php");
		exit();
	}

	// Update last activity timestamp
	$_SESSION['last_activity'] = time();

	// Enable error reporting for debugging
	ini_set('display_errors', 1);
	error_reporting(E_ALL);
} catch (Exception $e) {
    // Handle any potential exception during session handling, CSRF token generation, etc.
    echo "An error occurred: " . $e->getMessage();
    // Optionally, log the error for further debugging
    $logFile = 'error_log.txt';
    $logMessage = "[" . date('Y-m-d H:i:s') . "] Error: " . $e->getMessage() . "\n";
    file_put_contents($logFile, $logMessage, FILE_APPEND);
    exit();
}

$host = "localhost";
$user = "u415861906_infosec2235";
$pass = "1nrmG~9]|zkZV>/K";
$db = "u415861906_infosec2235";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    error_log("Database connection error: " . $conn->connect_error);
    die("Unable to connect to the database. Please try again later.");
}

$conn->set_charset('utf8mb4');

// LOGIN REQUEST
if (isset($_POST['login'])) {
    try {
        // CSRF validation
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception("CSRF token validation failed.");
        }

        $username = trim($_POST['username']);
        $password = trim($_POST['password']);
        $current_time = date("Y-m-d H:i:s");

        // Block unsafe input patterns
        $unsafe_patterns = ['/select/i', '/insert/i', '/delete/i', '/drop/i', '/--/i', '/<script>/i', '/<\/script>/i', '/<.*?>/i'];
        foreach ($unsafe_patterns as $pattern) {
            if (preg_match($pattern, $username) || preg_match($pattern, $password)) {
                throw new Exception("Unsafe input detected for user: $username");
            }
        }

		 // Context-based Access Control:

		// 1. IP Address Check
		//$user_ip = $_SERVER['REMOTE_ADDR'];
		//$allowed_ips = ['192.168.1.1', '203.0.113.5', '192.168.254.254']; // Example IPs, you can add more
		//if (!in_array($user_ip, $allowed_ips)) {
			//echo "Access denied from this IP address.";
			//exit();
	   //}

		// 2. Device Check
		//$user_agent = $_SERVER['HTTP_USER_AGENT'];
		//$trusted_devices = ['Chrome on Windows', 'Firefox on Mac']; // Example devices
		//$device_trusted = false;
		//foreach ($trusted_devices as $device) {
		   // if (strpos($user_agent, $device) !== false) {
			   // $device_trusted = true;
			   // break;
		   // }
	   // }

	   // if (!$device_trusted) {
			//echo "Untrusted device. Please verify your device.";
			//exit();
	   // }

        // 3. Time-Based Access Control
        $current_hour = date("H");
        if (($current_hour >= 23 || $current_hour < 4) && in_array($role, ['Doctor', 'Receptionist'])) {
            throw new Exception("Access is restricted from 11 PM to 4 AM for your role.");
        }

        // CAPTCHA verification based on failed login attempts
        if (isset($_SESSION['show_captcha']) && $_SESSION['show_captcha']) {
            $recaptcha_secret = '6Ld3o8MqAAAAABFh3mglNnkssLhEgBMc5JqpLKdP'; // Replace with your reCAPTCHA secret key
            $recaptcha_response = $_POST['g-recaptcha-response'];

            $recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify';
            $data = [
                'secret' => $recaptcha_secret,
                'response' => $recaptcha_response
            ];

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $recaptcha_verify_url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($ch);
            curl_close($ch);

            $recaptcha_data = json_decode($response);
            if (!$recaptcha_data->success) {
                throw new Exception("CAPTCHA validation failed.");
            }
        }

        $_SESSION['username'] = $username; // Save the username in session (you can add other session variables like user_id)
        
        // Log the successful login
        $logMessage = "[$current_time][INFO] - User $username logged in successfully.\n";
        $logFile = 'log.txt'; // Path to the log file
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            throw new Exception("Error writing to log file.");
        }

        // Failed login attempt check
        $sql_failed = "SELECT * FROM failed_logins WHERE username = ?";
        $stmt_failed = $conn->prepare($sql_failed);
        if (!$stmt_failed) {
            throw new Exception("Database error: " . $conn->error);
        }
        $stmt_failed->bind_param("s", $username);
        $stmt_failed->execute();
        $failed_result = $stmt_failed->get_result();

        $failed_attempts = 0;
        $locked_until = null;

        if ($failed_result->num_rows > 0) {
            $failed_row = $failed_result->fetch_assoc();
            $failed_attempts = $failed_row['failed_attempts'];
            $locked_until = $failed_row['locked_until'];

            // Check if account is locked
            if ($locked_until && strtotime($locked_until) > time()) {
                throw new Exception("Account locked. Try again after " . $locked_until);
            } elseif ($locked_until && strtotime($locked_until) <= time()) {
                // Reset lock time after 10 minutes
                $sql_unlock = "UPDATE failed_logins SET failed_attempts = 0, locked_until = NULL WHERE username = ?";
                $stmt_unlock = $conn->prepare($sql_unlock);
                if (!$stmt_unlock) {
                    throw new Exception("Database error: " . $conn->error);
                }
                $stmt_unlock->bind_param("s", $username);
                $stmt_unlock->execute();
            }
        }

        // User authentication
        $sql = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            throw new Exception("Database error: " . $conn->error);
        }
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            if (password_verify($password, $row['password'])) {
                // Successful login: reset failed attempts
                $sql_reset = "DELETE FROM failed_logins WHERE username = ?";
                $stmt_reset = $conn->prepare($sql_reset);
                if (!$stmt_reset) {
                    throw new Exception("Database error: " . $conn->error);
                }
                $stmt_reset->bind_param("s", $username);
                $stmt_reset->execute();

                // Store session data in sessions table
                $session_id = session_id();
                $user_id = $row['user_id']; // Assuming user_id is in the users table
                $current_time = date("Y-m-d H:i:s");

                $sql_session = "INSERT INTO sessions (session_id, user_id, created_at, last_activity) VALUES (?, ?, ?, ?)";
                $stmt_session = $conn->prepare($sql_session);
                if (!$stmt_session) {
                    throw new Exception("Database error: " . $conn->error);
                }
                $stmt_session->bind_param("siss", $session_id, $user_id, $current_time, $current_time);
                $stmt_session->execute();

                session_regenerate_id(true);
                $_SESSION['username'] = $row['username'];
                $_SESSION['role'] = $row['role'];
                if ($row['role'] == 'Doctor') {
                    $_SESSION['doctor_id'] = $row['user_id'];
                }

                // Log successful login in audit_logs
                $sql_audit_log = "INSERT INTO audit_logs (username, event_type, ip_address, user_agent) 
                                  VALUES (?, 'successful_login', ?, ?)";
                $stmt_audit_log = $conn->prepare($sql_audit_log);
                if (!$stmt_audit_log) {
                    throw new Exception("Database error: " . $conn->error);
                }
                $stmt_audit_log->bind_param("sss", $username, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
                $stmt_audit_log->execute();

                // Redirect to dashboard
                header("Location: index.php");
                exit();
            } else {
                throw new Exception("Invalid username or password.");
            }
        } else {
            throw new Exception("Invalid username or password.");
        }
    } catch (Exception $e) {
        // Log the exception message
        $logMessage = "[$current_time][ERROR] - " . $e->getMessage() . "\n";
        $logFile = 'log.txt'; // Path to the log file
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }

        // Display a generic error message
        echo "An error occurred. Please try again later.";
    }
}





try {
    // Check if user is logged in, otherwise show login form
    if (!isset($_SESSION['role'])) {
        $show_login_form = true;
    } else {
        $show_login_form = false;
    }

    // Additional code logic here...

} catch (Exception $e) {
    // Handle any errors that may have occurred
    echo "An error occurred: " . $e->getMessage();
    // Optionally log the error to a file
    $logMessage = "[" . date("Y-m-d H:i:s") . "] [ERROR] - " . $e->getMessage() . "\n";
    file_put_contents('log.txt', $logMessage, FILE_APPEND);
}


try{
	//LOGOUT FROM ALL SESSIONS
	if (isset($_GET['logout_all'])) {
		$user_id = $_SESSION['user_id']; // Get the user ID
		
		$logMessage = "[$current_time] [INFO] - User $username logged out from all sessions.\n";
		$fileHandle = fopen('log.txt', 'a');
		if ($fileHandle) {
			fwrite($fileHandle, $logMessage);
			fclose($fileHandle);
		} else {
			throw new Exception("Error writing to log file.");
		}

		// Delete all sessions for the user
		$sql_delete_sessions = "DELETE FROM sessions WHERE user_id = ?";
		$stmt_delete_sessions = $conn->prepare($sql_delete_sessions);
		if ($stmt_delete_sessions === false) {
            throw new Exception("Error preparing SQL statement for session deletion.");
        }
		$stmt_delete_sessions->bind_param("i", $user_id);
		 if (!$stmt_delete_sessions->execute()) {
            throw new Exception("Error executing session deletion query.");
        }
		
	
		// Proceed with logging out the current session
		unset($_SESSION['csrf_token']);
		session_unset(); // Clear session variables
		session_destroy(); // Destroy the session on the server



		// Redirect to login page
		header("Location: index.php");
		exit();
	}
} catch (Exception $e) {
    // Handle any errors that may have occurred
    echo "An error occurred: " . $e->getMessage();
    // Optionally log the error to a file
    $logMessage = "[" . date("Y-m-d H:i:s") . "] [ERROR] - " . $e->getMessage() . "\n";
    file_put_contents('log.txt', $logMessage, FILE_APPEND);
}

try {
	//LOGOUT
	if (isset($_GET['logout'])) {
		$logMessage = "[$current_time] [INFO] - User $username logged out.\n";
		$fileHandle = fopen('log.txt', 'a');
		if ($fileHandle) {
			fwrite($fileHandle, $logMessage);
			fclose($fileHandle);
		} else {
			throw new Exception("Error writing to log file.");
		}
		unset($_SESSION['csrf_token']);
		session_unset(); // Clear session variables
		session_destroy(); // Destroy the session file on the server

		header("Location: index.php"); // Redirect to login page
		exit();
	}
} catch (Exception $e) {
    // Handle any errors that may have occurred
    echo "An error occurred: " . $e->getMessage();
    
    // Optionally log the error to a file
    $logMessage = "[" . date("Y-m-d H:i:s") . "] [ERROR] - " . $e->getMessage() . "\n";
    file_put_contents('log.txt', $logMessage, FILE_APPEND);
}

//RECEPTIONIST
//new patient 
function generatePatientID($conn) {
    do {
        // Generate a random Patient ID
        $randomID = 'PID' . str_pad(rand(0, 99999), 5, '0', STR_PAD_LEFT);

        // Check if the generated Patient ID already exists in the database
        $query = "SELECT patient_id FROM patients WHERE patient_id = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("s", $randomID);
        $stmt->execute();
        $stmt->store_result();

    } while ($stmt->num_rows > 0); // Keep generating a new ID if it already exists

    return $randomID; // Return the unique Patient ID
}

$patient_id = generatePatientID($conn);

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['form_type']) && $_POST['form_type'] === 'new_patient') {
    // Generate a unique Patient ID
    $patient_id = generatePatientID($conn); 
    
    // Clean and format the form inputs
    $first_name = ucwords(strtolower(trim($_POST['first_name'])));
    $last_name = ucwords(strtolower(trim($_POST['last_name'])));  
    $dob = $_POST['dob'];
    $gender = $_POST['gender'];
    $address = $_POST['address'];
    $phone = $_POST['phone'];
    $email = strtolower(trim($_POST['email']));

    // Prepare and execute the insert query
    $stmt = $conn->prepare("INSERT INTO patients (patient_id, first_name, last_name, date_of_birth, gender, address, phone_number, email, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())");
    $stmt->bind_param("ssssssss", $patient_id, $first_name, $last_name, $dob, $gender, $address, $phone, $email);

    if ($stmt->execute()) {
		$logMessage = "[$current_time][INFO][RECEPTIONIST] - New patient record created: $first_name $last_name (Patient ID: $patient_id)\n";
        $logFile = 'log.txt'; // Path to the log file
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
        echo "New patient record created successfully.";
		unset($_SESSION['csrf_token']);
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();
}

//new appointment
// Function to generate a unique appointment ID
function generateAppointmentID($conn) {
    do {
        $randomID = 'A' . str_pad(rand(1, 99999), 5, '0', STR_PAD_LEFT);
        $query = "SELECT appointment_id FROM appointments WHERE appointment_id = ?";
        $stmt = $conn->prepare($query);
        if ($stmt) {
            $stmt->bind_param("s", $randomID);
            $stmt->execute();
            $stmt->store_result();
        } else {
            die("Database error: " . $conn->error);
        }
    } while ($stmt->num_rows > 0);
    $stmt->close();
    return $randomID;
}

// Generate the unique Appointment ID
$appointmentID = generateAppointmentID($conn);

// Fetch patients from the patients table
$patients_query = "SELECT patient_id, first_name, last_name FROM patients";
$patients_result = $conn->query($patients_query);

// Fetch doctors from the users table where role is 'doctor'
$doctors_query = "SELECT user_id, full_name FROM users WHERE role = 'doctor'";
$doctors_result = $conn->query($doctors_query);

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['form_type']) && $_POST['form_type'] == "new_appointment") {
        $appointment_id = $_POST['appointment_id'] ?? uniqid('apt_');
        $patient_id = $_POST['patient_id'];
        $doctor_id = $_POST['doctor_id'];
        $appointment_date = $_POST['appointment_date'];
        $reason = $_POST['reason'];
        $status = $_POST['status'];

        $stmt = $conn->prepare("INSERT INTO appointments (appointment_id, patient_id, doctor_id, appointment_date, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
        $stmt->bind_param("ssssss", $appointment_id, $patient_id, $doctor_id, $appointment_date, $reason, $status);

        if ($stmt->execute()) {
            $logMessage = "[$current_time][INFO][RECEPTIONIST] - New appointment created: Appointment ID: $appointment_id, Patient ID: $patient_id, Doctor ID: $doctor_id, Appointment Date: $appointment_date, Status: $status\n";
            $logFile = 'log.txt'; // Path to the log file
            $fileHandle = fopen($logFile, 'a');
            if ($fileHandle) {
                fwrite($fileHandle, $logMessage);
                fclose($fileHandle);
            } else {
                echo "Error writing to log file.";
            }
            echo "Appointment record created successfully.";
        } else {
            echo "Error: " . $stmt->error;
        }
        $stmt->close();
    }
}

//DOCTOR
//view patient information section
$records = [];
$error_message = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['patient_id'])) {
    $patient_id = trim($_POST['patient_id']); // Trim to remove extra spaces

    // Debugging output
    echo "Patient ID: $patient_id"; // Check the value

    // Validate Patient ID format server-side
    if (preg_match('/^PID\d{5}$/', $patient_id)) {
		
		$logMessage = "[$current_time][INFO][Doctor]  - Valid Patient ID format: $patient_id\n";
        $logFile = 'log.txt'; // Path to the log file
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
		
        // Fetch records from the database with only patient_id (no doctor_id)
        $query = "SELECT visit_date, diagnosis, treatment, notes, doctor_id
                  FROM records 
                  WHERE patient_id = ?";
        
        if ($stmt = $conn->prepare($query)) {
            $stmt->bind_param('s', $patient_id); // Bind only patient_id
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $records = $result->fetch_all(MYSQLI_ASSOC);
				
				$logMessage = "[$current_time][INFO][Doctor]  - Records retrieved for Patient ID: $patient_id\n";
                $fileHandle = fopen($logFile, 'a');
                if ($fileHandle) {
                    fwrite($fileHandle, $logMessage);
                    fclose($fileHandle);
                } else {
                    echo "Error writing to log file.";
                }
            } else {
                // Debugging message if no records are found
                echo "No records found for Patient ID: $patient_id"; // Check the reason 
				
				$logMessage = "[$current_time][WARN][Doctor]  - No records found for Patient ID: $patient_id\n";
                $fileHandle = fopen($logFile, 'a');
                if ($fileHandle) {
                    fwrite($fileHandle, $logMessage);
                    fclose($fileHandle);
                } else {
                    echo "Error writing to log file.";
                }
            }
            $stmt->close();
        } else {
            $error_message = "Database query failed.";
			$logMessage = "[$current_time][ERROR][Doctor]  - Database query failed for Patient ID: $patient_id\n";
            $fileHandle = fopen($logFile, 'a');
            if ($fileHandle) {
                fwrite($fileHandle, $logMessage);
                fclose($fileHandle);
            } else {
                echo "Error writing to log file.";
            }
        }
    } else {
        $error_message = "Invalid Patient ID format. Please use the format PID followed by 5 digits (e.g., PID12345).";
		$logMessage = "[$current_time][ERROR][Doctor] - Invalid Patient ID format: $patient_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
}

//add new record section
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['form_type']) && $_POST['form_type'] === 'new_record') {
    // Get form inputs
    $patient_id = trim($_POST['patient_id']);
    $doctor_id = $_SESSION['doctor_id']; // Assuming doctor_id is stored in session
    $visit_date = $_POST['visit_date'];
    $diagnosis = $_POST['diagnosis'];
    $treatment = $_POST['treatment'];
    $notes = isset($_POST['notes']) ? $_POST['notes'] : '';

    // Validate Patient ID format
    if (preg_match('/^PID\d{5}$/', $patient_id)) {
		
		$logMessage = "[$current_time][INFO][DOCTOR] - Valid Patient ID format: $patient_id\n";
        $logFile = 'log.txt'; // Path to the log file
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
		
        // Prepare SQL statement to insert the new record
        $query = "INSERT INTO records (patient_id, doctor_id, visit_date, diagnosis, treatment, notes) 
                  VALUES (?, ?, ?, ?, ?, ?)";
        
        if ($stmt = $conn->prepare($query)) {
            // Bind the parameters to the prepared statement
            $stmt->bind_param('ssssss', $patient_id, $doctor_id, $visit_date, $diagnosis, $treatment, $notes);
            
            // Execute the query
            if ($stmt->execute()) {
                $success_message = "New record added successfully!";
				$logMessage = "[$current_time][INFO][DOCTOR] - New record added for Patient ID: $patient_id by Doctor ID: $doctor_id\n";
                $fileHandle = fopen($logFile, 'a');
                if ($fileHandle) {
                    fwrite($fileHandle, $logMessage);
                    fclose($fileHandle);
                } else {
                    echo "Error writing to log file.";
                }
            } else {
                $error_message = "Failed to add the record. Please try again.";
				$logMessage = "[$current_time][ERROR][DOCTOR] - Failed to add record for Patient ID: $patient_id\n";
                $fileHandle = fopen($logFile, 'a');
                if ($fileHandle) {
                    fwrite($fileHandle, $logMessage);
                    fclose($fileHandle);
                } else {
                    echo "Error writing to log file.";
                }
            }
            $stmt->close();
        } else {
            $error_message = "Database query failed.";
			$logMessage = "[$current_time][ERROR][DOCTOR] - Database query failed while adding record for Patient ID: $patient_id\n";
            $fileHandle = fopen($logFile, 'a');
            if ($fileHandle) {
                fwrite($fileHandle, $logMessage);
                fclose($fileHandle);
            } else {
                echo "Error writing to log file.";
            }
        }
    } else {
        $error_message = "Invalid Patient ID format. Please use the format PID followed by 5 digits (e.g., PID12345).";
		 $logMessage = "[$current_time][ERROR][DOCTOR] - Invalid Patient ID format: $patient_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
}

//ADMIN
//NEW USER CREATION
if (isset($_POST['add_user'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $role = $_POST['role'];

    // Check for missing required fields
    if (empty($username) || empty($password) || empty($role)) {
        echo "Please fill all the required fields.";
        exit();
    }

    // Sanitize and format full name (only if provided)
    $full_name = isset($_POST['full_name']) ? $_POST['full_name'] : '';
    if (!empty($full_name)) {
        $full_name = preg_replace("/[^a-zA-Z\s.]/", "", $full_name); // Remove invalid characters
        $full_name = ucwords(strtolower($full_name)); // Capitalize first letters
    }

    // Validate email (only if provided)
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    if (!empty($email)) {
        $email = strtolower(str_replace(' ', '', $email)); // Convert to lowercase and remove spaces
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo "Invalid email address.";
            exit; // Stop execution if email is invalid
        }
    }

    // Validate phone number (only if provided)
    $phone_number = isset($_POST['phone_number']) ? $_POST['phone_number'] : '';
    if (!empty($phone_number)) {
        if (!preg_match("/^\d{11}$/", $phone_number)) {
            echo "Phone number must be exactly 11 digits.";
            exit; // Stop execution if phone number is invalid
        }
    }

    // Password strength check (optional but recommended)
    if (strlen($password) < 8) {
        echo "Password must be at least 8 characters long.";
        exit();
    }

    // Hash the password using bcrypt
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Prepare the SQL query
    $sql = "INSERT INTO users (username, password, role, full_name, email, phone_number) 
            VALUES (?, ?, ?, ?, ?, ?)";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssssi", $username, $hashedPassword, $role, $full_name, $email, $phone_number);

    // Execute the query
    if ($stmt->execute()) {
		$logMessage = "[$current_time][INFO][ADMIN] - User created successfully: $username with role: $role\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
        echo "User added successfully.";
    } else {
        echo "Error: " . $conn->error;
    }
}



//USER TABLE
//delete user information
if (isset($_GET['delete_user_id'])) {
    $delete_user_id = $_GET['delete_user_id']; 

    // SQL query to delete the user permanently from the database
    $delete_query = "DELETE FROM users WHERE user_id = ?";
    $stmt = $conn->prepare($delete_query);
    $stmt->bind_param("s", $delete_user_id);

    // Execute the query
    if ($stmt->execute()) {
        echo "<script>alert('User deleted successfully!'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - User deleted successfully: User ID $delete_user_id\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "<script>alert('Failed to delete user. Please try again.');</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to delete User ID: $delete_user_id\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }

    $stmt->close(); 
}

//edit user information
if (isset($_GET['edit_user_id'])) {
    $edit_user_id = $_GET['edit_user_id'];

    // Fetch user details
    $edit_query = "SELECT * FROM users WHERE user_id = ?";
    $stmt = $conn->prepare($edit_query);
    $stmt->bind_param("s", $edit_user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $edit_user = $result->fetch_assoc();
		$logMessage = "[$current_time][INFO][ADMIN] - Retrieved details for User ID: $edit_user_id\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "<script>alert('User not found.'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - User not found: User ID $edit_user_id\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }

    $stmt->close();
}

//update user information
if (isset($_POST['update_user'])) {
    $user_id = $_POST['edit_user_id'];
    $username = $_POST['username'];
    $role = $_POST['role'];

    // Sanitize and format full name (only if provided)
    $full_name = $_POST['full_name'];
    if (!empty($full_name)) {
        $full_name = preg_replace("/[^a-zA-Z\s.]/", "", $full_name); 
        $full_name = ucwords(strtolower($full_name)); 
    }

    // Validate email (only if provided)
    $email = $_POST['email'];
    if (!empty($email)) {
        $email = strtolower(str_replace(' ', '', $email)); 
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo "Invalid email address.";
            exit; 
        }
    }

    // Validate phone number (only if provided)
    $phone_number = $_POST['phone_number'];
    if (!empty($phone_number)) {
        if (!preg_match("/^\d{11}$/", $phone_number)) {
            echo "Phone number must be exactly 11 digits.";
            exit; 
        }
    }

	if (strlen($password) < 8) {
        echo "Password must be at least 8 characters long.";
        exit();
    }
		
    $password = $_POST['password']; 

    // Update the user info
    if (!empty($password)) {
        // If a new password is provided, hash it
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $sql = "UPDATE users SET username = ?, password = ?, role = ?, full_name = ?, email = ?, phone_number = ? WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssssssi", $username, $hashedPassword, $role, $full_name, $email, $phone_number, $user_id);
    } else {
        // If no password is provided, don't update the password
        $sql = "UPDATE users SET username = ?, role = ?, full_name = ?, email = ?, phone_number = ? WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sssssi", $username, $role, $full_name, $email, $phone_number, $user_id);
    }

    if ($stmt->execute()) {
        $userUpdated = true;
        echo "User updated successfully.";
		 $logMessage = "[$current_time][INFO][ADMIN] - User updated successfully: $username (User ID: $user_id) with role: $role\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "Error: " . $conn->error;
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to update user: $username (User ID: $user_id). Error: $error_message\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
}

//PATIENT TABLE
// delete patient information
if (isset($_GET['delete_patient_id'])) {
    $patient_id_to_delete = $_GET['delete_patient_id'];

    // Prepare and execute the delete query
    $delete_patient_query = "DELETE FROM patients WHERE patient_id = ?";
    $stmt = $conn->prepare($delete_patient_query);
    $stmt->bind_param("s", $patient_id_to_delete);
    
    if ($stmt->execute()) {
        echo "<script>alert('Patient deleted successfully'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - Patient deleted successfully: Patient ID $patient_id_to_delete\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
		
    } else {
        echo "<script>alert('Error deleting patient');</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to delete patient: Patient ID $patient_id_to_delete. Error: $error_message\n";
		$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
    $stmt->close();
}


//edit patient information
if (isset($_GET['edit_patient_id'])) {
    $patient_id = $_GET['edit_patient_id'];
    $edit_patient_query = "SELECT * FROM patients WHERE patient_id = ?";
    $stmt = $conn->prepare($edit_patient_query);
    $stmt->bind_param("s", $patient_id);
	
    if($stmt->execute()){
    $result = $stmt->get_result();
    $edit_patient = $result->fetch_assoc();
	
	$logMessage = "[$current_time][INFO][ADMIN] - Retrieved patient details for editing: Patient ID $patient_id\n";
	$fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
		}else {
			$error_message = $conn->error;
			$logMessage = "[$current_time][ERROR][ADMIN] - Failed to retrieve patient details: Patient ID $patient_id. Error: $error_message\n";
			$fileHandle = fopen($logFile, 'a');
				if ($fileHandle) {
					fwrite($fileHandle, $logMessage);
					fclose($fileHandle);
				} else {
					echo "Error writing to log file.";
				}
		}
	$stmt->close();
}

//update patient information
if (isset($_POST['update_patient'])) {
    // Get the updated values from the form
    $patient_id = $_POST['edit_patient_id'];
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $date_of_birth = $_POST['date_of_birth'];
    $gender = $_POST['gender'];
    $address = trim($_POST['address']);
    $phone_number = trim($_POST['phone_number']);
    $email = trim($_POST['email']);

    
    if (empty($first_name) || empty($last_name) || empty($date_of_birth) || empty($gender) || empty($address) || empty($phone_number) || empty($email)) {
        echo "<script>alert('All fields are required. Please fill in all the details.'); window.history.back();</script>";
        exit;
    }

    
    if (!preg_match("/^\+?[0-9]{11}$/", $phone_number)) {
        echo "<script>alert('Invalid phone number. Please enter a valid 11-digit phone number.'); window.history.back();</script>";
        exit;
    }

    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email address. Please enter a valid email.'); window.history.back();</script>";
        exit;
    }

    
    $update_patient_query = "UPDATE patients SET first_name = ?, last_name = ?, date_of_birth = ?, gender = ?, address = ?, phone_number = ?, email = ? WHERE patient_id = ?";
    $stmt = $conn->prepare($update_patient_query);
    $stmt->bind_param("ssssssss", $first_name, $last_name, $date_of_birth, $gender, $address, $phone_number, $email, $patient_id);

    
    if ($stmt->execute()) {
        echo "<script>alert('Patient updated successfully'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - Patient updated successfully: Patient ID $patient_id\n";
		$fileHandle = fopen($logFile, 'a');
		if ($fileHandle) {
			fwrite($fileHandle, $logMessage);
			fclose($fileHandle);
		} else {
			echo "Error writing to log file.";
		}
    } else {
        echo "<script>alert('Error updating patient. Please try again later.');</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to update patient: Patient ID $patient_id. Error: $error_message\n";
		$fileHandle = fopen($logFile, 'a');
		if ($fileHandle) {
			fwrite($fileHandle, $logMessage);
			fclose($fileHandle);
		} else {
			echo "Error writing to log file.";
		}
    }
    $stmt->close();
}

//APPOINTMENT TABLE
//delete appointment information
if (isset($_GET['delete_appointment_id'])) {
    $appointment_id = $_GET['delete_appointment_id'];

    $delete_appointment_query = "DELETE FROM appointments WHERE appointment_id = ?";
    $stmt = $conn->prepare($delete_appointment_query);
    $stmt->bind_param("s", $appointment_id);

    if ($stmt->execute()) {
        echo "<script>alert('Appointment deleted successfully'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - Appointment deleted successfully: Appointment ID $appointment_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "<script>alert('Error deleting appointment');</script>";
		 $logMessage = "[$current_time][ERROR][ADMIN] - Failed to delete appointment: Appointment ID $appointment_id. Error: $error_message\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
    $stmt->close();
}

//edit appointment information
if (isset($_GET['edit_appointment_id'])) {
    $appointment_id = $_GET['edit_appointment_id'];
    $edit_appointment_query = "SELECT * FROM appointments WHERE appointment_id = ?";
    $stmt = $conn->prepare($edit_appointment_query);
    $stmt->bind_param("s", $appointment_id);
	
    if($stmt->execute()){
    $result = $stmt->get_result();
    $edit_appointment = $result->fetch_assoc();
	$logMessage = "[$current_time][INFO][ADMIN] - Retrieved appointment details for editing: Appointment ID $appointment_id\n";
    $fileHandle = fopen($logFile, 'a');
		if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
	} else{
		$error_message = $conn->error;
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to retrieve appointment details for Appointment ID $appointment_id. Error: $error_message\n";
		$fileHandle = fopen($logFile, 'a');
		if ($fileHandle) {
			fwrite($fileHandle, $logMessage);
			fclose($fileHandle);
		} else {
			echo "Error writing to log file.";
		}
	}
    $stmt->close();
}

//update appointment information
if (isset($_POST['update_appointment'])) {
    $appointment_id = $_POST['edit_appointment_id'];
    $appointment_date = $_POST['appointment_date'];
    $reason = trim($_POST['reason']);
    $status = $_POST['status'];

    // Check if required fields are filled
    if (empty($appointment_date) || empty($reason) || empty($status)) {
        echo "<script>alert('All required fields must be filled'); window.history.back();</script>";
        exit;
    }

    // Prepare the update query
    $update_appointment_query = "UPDATE appointments SET appointment_date = ?, reason = ?, status = ? WHERE appointment_id = ?";
    $stmt = $conn->prepare($update_appointment_query);
    $stmt->bind_param("ssss", $appointment_date, $reason, $status, $appointment_id);

    if ($stmt->execute()) {
        echo "<script>alert('Appointment updated successfully'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - Appointment updated successfully: Appointment ID $appointment_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "<script>alert('Error updating appointment');</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to update appointment: Appointment ID $appointment_id. Error: $error_message\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
    $stmt->close();
}

//RECORD TABLE
//delete record information
if (isset($_GET['delete_record_id'])) {
    $record_id = $_GET['delete_record_id'];

    $delete_record_query = "DELETE FROM records WHERE record_id = ?";
    $stmt = $conn->prepare($delete_record_query);
    $stmt->bind_param("s", $record_id);

    if ($stmt->execute()) {
        echo "<script>alert('Record deleted successfully'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - Record deleted successfully: Record ID $record_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "<script>alert('Error deleting record');</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to delete record: Record ID $record_id. Error: $error_message\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
    $stmt->close();
}

//edit record information
if (isset($_GET['edit_record_id'])) {
    $record_id = $_GET['edit_record_id'];
    $edit_record_query = "SELECT * FROM records WHERE record_id = ?";
    $stmt = $conn->prepare($edit_record_query);
    $stmt->bind_param("s", $record_id);
	
	
    if($stmt->execute()){
    $result = $stmt->get_result();
    $edit_record = $result->fetch_assoc();
	$logMessage = "[$current_time][INFO][ADMIN] - Retrieved record details for editing: Record ID $record_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
	}else{
		$error_message = $conn->error;
        $logMessage = "[$current_time][ERROR][ADMIN] - Failed to retrieve record details: Record ID $record_id. Error: $error_message\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
	}
    $stmt->close();
}

//update record information
if (isset($_POST['update_record'])) {
    $record_id = $_POST['edit_record_id'];
    $visit_date = $_POST['visit_date'];
    $diagnosis = trim($_POST['diagnosis']);
    $treatment = trim($_POST['treatment']);
    $notes = trim($_POST['notes']);

    // Validate required fields
    if (empty($visit_date) || empty($diagnosis) || empty($treatment)) {
        echo "<script>alert('All required fields must be filled'); window.history.back();</script>";
        exit;
    }

    // Prepare the update query
    $update_record_query = "UPDATE records SET visit_date = ?, diagnosis = ?, treatment = ?, notes = ? WHERE record_id = ?";
    $stmt = $conn->prepare($update_record_query);
    $stmt->bind_param("sssss", $visit_date, $diagnosis, $treatment, $notes, $record_id);

    if ($stmt->execute()) {
        echo "<script>alert('Record updated successfully'); window.location.href = 'index.php';</script>";
		$logMessage = "[$current_time][INFO][ADMIN] - Updated record: Record ID $record_id\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    } else {
        echo "<script>alert('Error updating record');</script>";
		$logMessage = "[$current_time][ERROR][ADMIN] - Failed to update record: Record ID $record_id. Error: $error_message\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }
    }
    $stmt->close();
}

//GENERATE REPORT
//date ranging
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['generate_report'])) {
    $date_from = $_POST['date_from'];
    $date_to = $_POST['date_to'];

    if (!empty($date_from) && !empty($date_to) && $date_from <= $date_to) {
        $report_data = [];

        // Fetch Users
        $query_users = "SELECT * FROM users WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_users);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['users'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
		
		$logMessage = "[$current_time][INFO][ADMIN] - Fetched users data for report between $date_from and $date_to\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }

        // Fetch Patients
        $query_patients = "SELECT * FROM patients WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_patients);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['patients'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
		
		$logMessage = "[$current_time][INFO][ADMIN] - Fetched patients data for report between $date_from and $date_to\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }

        // Fetch Appointments
        $query_appointments = "SELECT * FROM appointments WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_appointments);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['appointments'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
		
		$logMessage = "[$current_time][INFO][ADMIN] - Fetched appointments data for report between $date_from and $date_to\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }

        // Fetch Records
        $query_records = "SELECT * FROM records WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_records);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['records'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
		
		$logMessage = "[$current_time][INFO][ADMIN] - Fetched records data for report between $date_from and $date_to\n";
        $fileHandle = fopen($logFile, 'a');
        if ($fileHandle) {
            fwrite($fileHandle, $logMessage);
            fclose($fileHandle);
        } else {
            echo "Error writing to log file.";
        }

    } else {
        echo "<script>alert('Please select a valid date range.');</script>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.1/css/all.min.css">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/select2/4.0.13/css/select2.min.css" rel="stylesheet" />
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js" 
				integrity="sha384-KyZXEAg3QhqLMpG8r+Knujsl5+5hb7x2mXKzJ5x5U5PA5M/Ub52zYOhF+prc4d6z" 
				crossorigin="anonymous"></script>

		<script src="https://cdnjs.cloudflare.com/ajax/libs/select2/4.0.13/js/select2.min.js"
				integrity="sha384-4qNfl5l7qYy3qiyNTqTHKJ0z3eb4k9PoX4m3VVJv+2Zm10f5t3X4pAp8DjJw3Jv9"
				crossorigin="anonymous"></script>
        
        <link rel="icon" href="logo.png" type="image/png">
        <title>Hikari Care</title>

        <style>
*{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: "poppins", sans-serif;
}

body{
    background-color: #98ff98;
    background: linear-gradient(to left, #98ff98, #a177ca);
}

.container{
    background: #fff;
    width: 450px;
    padding: 1.5rem;
    margin: 50px auto;
    border-radius: 10px;
    box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);
}

form{
    margin: 0.2rem;
}

.form-title{
    font-size: 1.5rem;
    font-weight: bold;
    text-align: center;
    padding: 1.3rem;
    margin-bottom: 0.4rem;
}

input{
    color: inherit;
    width: 100%;
    background-color: transparent;
    border: none;
    border-bottom: 1px solid #757575;
    padding-left: 1.5rem;
    font-size: 15px;
}

.input-group{
    padding: 1% 0;
    position: relative;
}

.input-group i{
    position: absolute;
    color: black;
}

input:focus{
    background-color: transparent;
    outline: transparent;
    border-bottom: 2px solid hsl(327, 90%, 28%);
}

input::placeholder{
    color: transparent;
}

label{
    color: #757575;
    position: relative;
    left: 1.2rem;
    top: -1.3rem;
    cursor: auto;
    transition: 0.3s ease all;
}

input:focus~label,input:not(:placeholder-shown)~label{
    top: -3em;
    color: hsl(327, 90%, 28%);
    font-size: 15px;
}

.btn{
    font-size: 1.1rem;
    padding: 8px 0;
    border-radius: 5px;
    outline: none;
    border: none;
    width: 100%;
    background-color: rgb(125, 125, 235);
    color: white;
    cursor: pointer;
    transition: 0.9s;
}

.btn:hover{
    background: #07001f;
}

.section{
    border: 2px solid #ccc;
    padding: 15px;
    margin-bottom: 10px;
    display: none;
}


.input-group {
    margin-bottom: 1.5rem;
    /* Adds space between fields */
    display: flex;
    flex-direction: column;
    /* Stack the label and input vertically */
    align-items: flex-start;
    /* Align left */
}

.input-group label {
    font-weight: bold;
    color: #333;
    margin-bottom: 5px;
    /* Adds space between label and input/textarea */
    width: 100%;
    /* Ensures label takes full width */
}

.input-group input,
.input-group textarea {
    width: 100%;
    /* Ensure input and textarea take the full width */
    padding: 10px;
    /* Padding inside the input field */
    border: 1px solid #ddd;
    border-radius: 5px;
    box-sizing: border-box;
    /* Include padding in width calculation */
}

.input-group textarea {
    resize: vertical;
    /* Allow vertical resizing */
    height: 120px;
    /* Adjust height for better space */
}

.input-group input:focus,
.input-group textarea:focus {
    border-color: #3273dc;
}

textarea {
    resize: vertical;
    height: 120px;
    margin-top: 5px;
}

.logo {
    width: 150px; /* Adjust the width as needed */
    height: auto;
    display: block;
    margin: 0 auto; /* Center the logo */
}

    </style>
    </head>
    <body>
        
        <!-- LOG IN-->
        <?php if ($show_login_form) { ?>
            <nav class="container" id="login">
            <img src="full_logo.png" alt="Hikari Care Logo" class="logo">
                <form id="loginForm" action="index.php" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="input-group">
                        <i class="fas fa-user"></i>
                        <input type="text" id="username" name="username" placeholder="Username" required>
                        <label for="username">Username</label>
                    </div>
                    <div class="input-group">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="password" name="password" placeholder="Password" required>
                        <label for="password">Password</label>
                    </div>
                    <?php if (isset($_SESSION['show_captcha']) && $_SESSION['show_captcha']) { ?>
                        <!-- Show CAPTCHA if required -->
                        <div class="g-recaptcha" data-sitekey="6Ld3o8MqAAAAAN6QPe71nJSW0Do2FPJxBRT3DpOD" data-callback="enablecaptchabtn"></div><br>
                        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
                        <script>
                            function enablecaptchabtn(){
                                document.getElementById("submitcaptcha").disabled = false;
                            }
                        </script>
                    <?php } ?>

                    <input type="submit" class="btn" id="submitcaptcha" 
                        value="Log In" 
                        name="login" 
                        <?php if (isset($_SESSION['show_captcha']) && $_SESSION['show_captcha']) { echo 'disabled="disabled"'; } ?>>
                </form>
            </nav>
        <?php } else { ?>

            <!-- If logged in, hide the login form -->
            <nav class="container" id="login" style="display: none;">
                <h1 class="form-title">Hikari Care</h1>
            </nav>






                <!-- Receptionist Section-->
                <?php if ($_SESSION['role'] == 'Receptionist') { ?>
                    <div id="receptionist-section" class="section" style="display:block;">
                        <h2>Receptionist Dashboard</h2>
                        <p>Welcome, Receptionist! Manage appointments of the patients.</p><br><br><br>

                    <!--NEW PATIENT-->
                    <form method="POST" style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                        <input type="hidden" name="form_type" value="new_patient">
                        <h3>NEW PATIENT</h3>
                        <table>
                            <tr>
                                <th>Patient ID</th>
                                <th>First Name</th>
                                <th>Last Name</th>
                                <th>Date of Birth</th>
                                <th>Gender</th>
                                <th>Address</th>
                                <th>Phone Number</th>
                                <th>Email</th>
                            </tr>
                            <tr>
                                <td><input type="text" id="patient_id" name="patient_id" value="<?php echo htmlspecialchars($patient_id); ?>" required disabled /></td>
                                <td><input type="text" name="first_name" pattern="[a-zA-Z\s]+" title="First name should only contain letters." required /></td>
                                <td><input type="text" name="last_name" pattern="[a-zA-Z\s]+" title="Last name should only contain letters." required /></td>
                                <td><input type="date" name="dob" max="<?php echo date('Y-m-d'); ?>" title="Date of birth cannot be in the future." required /></td>
                                <td>
                                    <select name="gender" required>
                                        <option value="">Select</option>
                                        <option value="male">Male</option>
                                        <option value="female">Female</option>
                                        <option value="other">Other</option>
                                    </select>
                                </td>
                                <td><input type="text" name="address" required /></td>
                                <td><input type="tel" name="phone" pattern="[0-9]{11}" title="Phone number must be exactly 11 digits." required /></td>
                                <td><input type="email" name="email" pattern="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" title="Please enter a valid email address with '@' and '.'" required /></td>
                            </tr>
                        </table>
                        <button type="submit" class="btn">Submit</button>
                    </form>

                    <!--APPOINTMENT-->
                    <form method="POST" style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
					<input type="hidden" name="form_type" value="new_appointment">
					<h3>APPOINTMENT</h3>
					<table>
						<tr>
							<th>Appointment ID</th>
							<th>Patient</th>
							<th>Doctor</th>
							<th>Appointment Date</th>
							<th>Reason</th>
							<th>Status</th>
						</tr>
						<tr>
							<!-- Appointment ID -->
							<td>
								<input type="hidden" name="appointment_id" value="<?php echo $appointmentID; ?>" />
								<span><?php echo $appointmentID; ?></span>
							</td>

							<!-- Patient Dropdown -->
							<td>
								&emsp;
								<select name="patient_id" class="select2" required>
									<option value="">Select Patient</option>
									<?php 
									if ($patients_result->num_rows > 0) {
										while ($patient = $patients_result->fetch_assoc()) { ?>
											<option value="<?php echo $patient['patient_id']; ?>">
												<?php echo htmlspecialchars($patient['first_name'] . ' ' . $patient['last_name']); ?>
											</option>
										<?php } 
									} ?>
								</select>
							</td>

							<!-- Doctor Dropdown -->
							<td>
								&emsp;
								<select name="doctor_id" required>
									<option value="">Select Doctor</option>
									<?php 
									if ($doctors_result->num_rows > 0) {
										while ($doctor = $doctors_result->fetch_assoc()) { ?>
											<option value="<?php echo $doctor['user_id']; ?>">
												<?php echo htmlspecialchars($doctor['full_name']); ?>
											</option>
										<?php } 
									} ?>
								</select>
							</td>

							<!-- Appointment Date -->
							<td>
								&emsp;
								<input type="datetime-local" name="appointment_date" required />
							</td>

							<!-- Reason -->
							<td>
								&emsp;
								&emsp;
								&emsp;
								&emsp;
								<input type="text" name="reason" required />
							</td>

							<!-- Status -->
							<td>
								&emsp;
								<select name="status" required>
									<option value="Scheduled">Scheduled</option>
									<option value="Completed">Completed</option>
									<option value="Canceled">Canceled</option>
								</select>
							</td>
						</tr>
					</table>
					<button type="submit" class="btn">Submit</button>
				</form>

				<!-- Initialize Select2 -->
				<script>
				$(document).ready(function() {
					$('.select2').select2();
				});
				</script>


                    <!-- APPOINTMENT TABLE -->
                    <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Manage Appointments</h1>
                            <table border="1" style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th>Appointment ID</th>
                                        <th>Patient ID</th>
                                        <th>Doctor ID</th>
                                        <th>Appointment Date</th>
                                        <th>Reason</th>
                                        <th>Status</th>
                                        <th>Created At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    // Fetch all appointments from the database
                                    $appointments_query = "SELECT * FROM appointments";
                                    $appointments_result = $conn->query($appointments_query);

                                    if ($appointments_result->num_rows > 0) {
                                        while ($appointment = $appointments_result->fetch_assoc()) {
                                            echo '<tr>
                                                    <td>' . $appointment['appointment_id'] . '</td>
                                                    <td>' . $appointment['patient_id'] . '</td>
                                                    <td>' . $appointment['doctor_id'] . '</td>
                                                    <td>' . $appointment['appointment_date'] . '</td>
                                                    <td>' . htmlspecialchars($appointment['reason']) . '</td>
                                                    <td>' . $appointment['status'] . '</td>
                                                    <td>' . $appointment['created_at'] . '</td>
                                                    <td>
                                                        <a href="index.php?edit_appointment_id=' . $appointment['appointment_id'] . '">Edit</a> 
                                                        <a href="?delete_appointment_id=' . $appointment['appointment_id'] . '" onclick="return confirm(\'Are you sure you want to delete this appointment?\')">Delete</a>
                                                    </td>
                                                </tr>';
                                        }
                                    } else {
                                        echo '<tr><td colspan="8">No appointments found.</td></tr>';
                                    }
                                    ?>
                                </tbody>
                            </table>
                        </div>

                        <?php if (isset($edit_appointment)) { ?>
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Edit Appointment</h1>
                            <form method="POST" action="">
                                <input type="hidden" name="edit_appointment_id" value="<?php echo $edit_appointment['appointment_id']; ?>">

                                <div class="input-group">
                                    <label for="patient_id">Patient ID:</label>
                                    <input type="text" id="patient_id" name="patient_id" value="<?php echo htmlspecialchars($edit_appointment['patient_id']); ?>" readonly><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="doctor_id">Doctor ID:</label>
                                    <input type="text" id="doctor_id" name="doctor_id" value="<?php echo htmlspecialchars($edit_appointment['doctor_id']); ?>" readonly><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="appointment_date">Appointment Date:</label>
                                    <input type="datetime-local" id="appointment_date" name="appointment_date" value="<?php echo date('Y-m-d\TH:i', strtotime($edit_appointment['appointment_date'])); ?>" required><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="reason">Reason:</label>
                                    <textarea id="reason" name="reason" required><?php echo htmlspecialchars($edit_appointment['reason']); ?></textarea><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="status">Status:</label>
                                    <select id="status" name="status" required>
                                        <option value="Scheduled" <?php echo ($edit_appointment['status'] == 'Scheduled') ? 'selected' : ''; ?>>Scheduled</option>
                                        <option value="Completed" <?php echo ($edit_appointment['status'] == 'Completed') ? 'selected' : ''; ?>>Completed</option>
                                        <option value="Canceled" <?php echo ($edit_appointment['status'] == 'Canceled') ? 'selected' : ''; ?>>Canceled</option>
                                    </select><br><br>
                                </div>

                                <button type="submit" name="update_appointment" class="btn">Update Appointment</button>
                            </form>
                        </div>
                        <?php } ?>


                        <br><br><br><a href="?logout=true" class="btn">Logout</a><br><br><br>
			            <a href="?logout_all=true" class="btn">Logout from All Sessions</a>
                    </div>





                <!-- Doctor Section-->
                <?php } elseif ($_SESSION['role'] == 'Doctor') { ?>
                    <div id="doctor-section" class="section" style="display:block;">
                        <h2>Doctor Dashboard</h2>
                        <p>Welcome, Doctor! Here you can view and manage patient records.</p><br><br><br>

                        <!-- View Patient Records Section -->
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h3>View Records</h3>
                            <form method="POST" action="">
                                <br><br><br>
                                <label for="view_patient_id">Enter Patient ID:</label>
                                <input type="text" id="view_patient_id" name="patient_id" placeholder="Use PID as the first input (e.g., PID12345)" required oninput="validateViewPID()">
                                <span id="view_error_message" style="color: red; display: none;">Please enter a valid Patient ID (e.g., PID12345)</span>
                                <button type="submit" class="btn">Search</button>
                            </form>

                            <script>
                                // Function to validate the input as PID followed by numbers for View Records
                                function validateViewPID() {
                                    const inputField = document.getElementById("view_patient_id");
                                    const errorMessage = document.getElementById("view_error_message");

                                    const pidPattern = /^PID\d{5}$/;

                                    if (!pidPattern.test(inputField.value)) {
                                        errorMessage.style.display = "inline";
                                    } else {
                                        errorMessage.style.display = "none"; 
                                    }
                                }
                            </script>

                            <?php if (!empty($records)) : ?>
                                <table style="width: 100%; border: 1px solid #ccc; margin-top: 20px;">
                                    <thead>
                                        <tr>
                                            <th>Visit Date</th>
                                            <th>Diagnosis</th>
                                            <th>Treatment</th>
                                            <th>Notes</th>
                                            <th>Doctor ID</th> <!-- Added Doctor ID column -->
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($records as $record) : ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($record['visit_date']); ?></td>
                                                <td><?php echo htmlspecialchars($record['diagnosis']); ?></td>
                                                <td><?php echo htmlspecialchars($record['treatment']); ?></td>
                                                <td><?php echo htmlspecialchars($record['notes']); ?></td>
                                                <td><?php echo htmlspecialchars($record['doctor_id']); ?></td> <!-- Display Doctor ID -->
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            <?php elseif (!empty($error_message)) : ?>
                                <p style="color: red;"><?php echo $error_message; ?></p>
                            <?php endif; ?>
                        </div>

                        <!-- Add New Record Section -->
                        <input type="hidden" name="form_type" value="new_record">
                        <div id="add-record-section" style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h3>Add New Record</h3><br><br><br>
                            <form method="POST" action="" id="add-record-form">
                                <input type="hidden" name="form_type" value="new_record">

                                <div class="input-group">
                                    <label for="add_patient_id">Patient ID:</label>
                                    <input type="text" id="add_patient_id" name="patient_id" placeholder="Use PID followed by 5 digits (e.g., PID12345)" required oninput="validateAddPID()"><br><br>
                                    <span id="add_error_message" style="color: red; display: none;">Please enter a valid Patient ID (e.g., PID12345 with exactly 5 digits)</span>
                                </div>

                                <div class="input-group">
                                    <label for="doctor_id">Doctor ID:</label>
                                    <input type="text" id="doctor_id" name="doctor_id" value="<?php echo $_SESSION['doctor_id']; ?>" readonly disabled><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="visit_date">Visit Date:</label>
                                    <input type="datetime-local" id="visit_date" name="visit_date" required><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="diagnosis">Diagnosis:</label>
                                    <textarea id="diagnosis" name="diagnosis" required></textarea><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="treatment">Treatment:</label>
                                    <textarea id="treatment" name="treatment" required></textarea><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="notes">Notes:</label>
                                    <textarea id="notes" name="notes"></textarea><br><br>
                                </div>

                                <button type="submit" class="btn">Add Record</button>
                            </form>
                        </div>

                        <script>
                            function validateAddPID() {
                                const inputField = document.getElementById("add_patient_id");
                                const errorMessage = document.getElementById("add_error_message");

                                const pidPattern = /^PID\d{5}$/;

                                if (!pidPattern.test(inputField.value)) {
                                    errorMessage.style.display = "inline"; // Show error message
                                } else {
                                    errorMessage.style.display = "none"; // Hide error message
                                }
                            }
                        </script>

                        <!-- PATIENT TABLE -->
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                                <h1>Manage Patients</h1>
                                <table border="1" style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                                    <thead>
                                        <tr>
                                            <th>Patient ID</th>
                                            <th>First Name</th>
                                            <th>Last Name</th>
                                            <th>Date of Birth</th>
                                            <th>Gender</th>
                                            <th>Address</th>
                                            <th>Phone Number</th>
                                            <th>Email</th>
                                            <th>Created At</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        // Fetch all patients from the database
                                        $patients_query = "SELECT * FROM patients";
                                        $patients_result = $conn->query($patients_query);

                                        if ($patients_result->num_rows > 0) {
                                            while ($patient = $patients_result->fetch_assoc()) {
                                                echo '<tr>
                                                        <td>' . htmlspecialchars($patient['patient_id']) . '</td>
                                                        <td>' . htmlspecialchars($patient['first_name']) . '</td>
                                                        <td>' . htmlspecialchars($patient['last_name']) . '</td>
                                                        <td>' . htmlspecialchars($patient['date_of_birth']) . '</td>
                                                        <td>' . htmlspecialchars($patient['gender']) . '</td>
                                                        <td>' . htmlspecialchars($patient['address']) . '</td>
                                                        <td>' . htmlspecialchars($patient['phone_number']) . '</td>
                                                        <td>' . htmlspecialchars($patient['email']) . '</td>
                                                        <td>' . htmlspecialchars($patient['created_at']) . '</td>
                                                        <td>
                                                            <a href="index.php?edit_patient_id=' . urlencode($patient['patient_id']) . '" >Edit</a> 
                                                            <a href="?delete_patient_id=' . urlencode($patient['patient_id']) . '" onclick="return confirm(\'Are you sure you want to delete this patient?\')">Delete</a>
                                                        </td>
                                                    </tr>';
                                            }
                                        } else {
                                            echo '<tr><td colspan="10">No patients found.</td></tr>';
                                        }
                                        ?>
                                    </tbody>
                                </table>
                            </div>

                            <?php if (isset($edit_patient)) { ?>
                            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                                <h1>Edit Patient</h1>
                                <form method="POST" action="">
                                    <input type="hidden" name="edit_patient_id" value="<?php echo $edit_patient['patient_id']; ?>">

                                    <div class="input-group">
                                        <label for="first_name">First Name:</label>
                                        <input type="text" id="first_name" name="first_name" value="<?php echo htmlspecialchars($edit_patient['first_name']); ?>" 
                                            pattern="[A-Za-z\s]+" title="First name can only contain letters and spaces." required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="last_name">Last Name:</label>
                                        <input type="text" id="last_name" name="last_name" value="<?php echo htmlspecialchars($edit_patient['last_name']); ?>"
                                            pattern="[A-Za-z\s]+" title="Last name can only contain letters and spaces." required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="date_of_birth">Date of Birth:</label>
                                        <input type="date" id="date_of_birth" name="date_of_birth" value="<?php echo htmlspecialchars($edit_patient['date_of_birth']); ?>" required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="gender">Gender:</label>
                                        <select id="gender" name="gender" required>
                                            <option value="Male" <?php echo ($edit_patient['gender'] == 'Male') ? 'selected' : ''; ?>>Male</option>
                                            <option value="Female" <?php echo ($edit_patient['gender'] == 'Female') ? 'selected' : ''; ?>>Female</option>
                                            <option value="Other" <?php echo ($edit_patient['gender'] == 'Other') ? 'selected' : ''; ?>>Other</option>
                                        </select><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="address">Address:</label>
                                        <textarea id="address" name="address"><?php echo htmlspecialchars($edit_patient['address']); ?></textarea><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="phone_number">Phone Number:</label>
                                        <input type="tel" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($edit_patient['phone_number']); ?>" pattern="^\+?[0-9]{11}$" title="Phone number must be 10 digits" required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="email">Email:</label>
                                        <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($edit_patient['email']); ?>"
                                            oninput="this.value = this.value.toLowerCase()" required placeholder="Enter a valid email address"><br><br>
                                    </div>

                                    <button type="submit" name="update_patient" class="btn">Update Patient</button>
                                </form>
                            </div>
                        <?php } ?>

                        <br><br><br><br><br><a href="?logout=true" class="btn">Logout</a><br><br><br>
			            <a href="?logout_all=true" class="btn">Logout from All Sessions</a>
                    </div>





                <!-- Admin Section-->
                <?php } elseif ($_SESSION['role'] == 'Admin') { ?>
                    <div id="admin-section" class="section" style="display:block;">
                        <h2>Admin Dashboard</h2>
                        <p>Welcome, Admin! Here you can manage system settings and accesses.</p>

                            <!-- NEW USER CREATION-->
                            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                                <h1>Add User to Database</h1><br>
                                <form method="POST" action="">
                                    <div class="input-group">
                                    <label for="username">Username:</label>
                                    <input type="text" id="username" name="username" required><br><br>
                                    </div>

                                    <div class="input-group">
                                    <label for="password">Password:</label>
                                    <input type="password" id="password" name="password" required><br><br>
                                    </div>

                                    <div class="input-group">
                                    <label for="role">Role:</label>
                                    <select id="role" name="role" required>
                                        <option value="Admin">Admin</option>
                                        <option value="Doctor">Doctor</option>
                                        <option value="Receptionist">Receptionist</option>
                                    </select><br><br>
                                    </div>

                                    <div class="input-group">
                                    <label for="full_name">Full Name:</label>
                                    <input type="text" id="full_name" name="full_name"><br><br>
                                    </div>

                                    <div class="input-group">
                                    <label for="email">Email:</label>
                                    <input type="email" id="email" name="email"><br><br>
                                    </div>

                                    <div class="input-group">
                                    <label for="phone_number">Phone Number:</label>
                                    <input type="number" id="phone_number" name="phone_number"><br><br>
                                    </div>

                                    <button type="submit" name="add_user" class="btn">Add User</button>
                                </form>
                            </div>

                            <!-- USER TABLE -->
                            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Manage Users</h1>
                            <table border="1" style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th>User ID</th>
                                        <th>Username</th>
                                        <th>Role</th>
                                        <th>Full Name</th>
                                        <th>Email</th>
                                        <th>Phone Number</th>
                                        <th>Created At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    // Fetch all users from the database
                                    $users_query = "SELECT * FROM users";
                                    $users_result = $conn->query($users_query);

                                    if ($users_result->num_rows > 0) {
                                        while ($user = $users_result->fetch_assoc()) {
                                            echo '<tr>
                                                    <td>' . $user['user_id'] . '</td>
                                                    <td>' . $user['username'] . '</td>
                                                    <td>' . $user['role'] . '</td>
                                                    <td>' . $user['full_name'] . '</td>
                                                    <td>' . $user['email'] . '</td>
                                                    <td>' . $user['phone_number'] . '</td>
                                                    <td>' . $user['created_at'] . '</td>
                                                    <td>
                                                        <a href="index.php?edit_user_id=' . $user['user_id'] . '" >Edit</a> 
                                                        <a href="?delete_user_id=' . $user['user_id'] . '" onclick="return confirm(\'Are you sure you want to delete this user?\')">Delete</a>
                                                    </td>
                                                </tr>';
                                        }
                                    } else {
                                        echo '<tr><td colspan="8">No users found.</td></tr>';
                                    }
                                    ?>
                                </tbody>
                            </table>
                            </div>

                            <?php if (!isset($userUpdated)) {?>
                            <?php if (isset($edit_user)) { ?>
                            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                                <h1>Edit User</h1>
                                <form method="POST" action="">
                                    <input type="hidden" name="edit_user_id" value="<?php echo $edit_user['user_id']; ?>">

                                    <div class="input-group">
                                        <label for="username">Username:</label>
                                        <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($edit_user['username']); ?>" required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="role">Role:</label>
                                        <select id="role" name="role" required>
                                            <option value="Admin" <?php echo ($edit_user['role'] == 'Admin') ? 'selected' : ''; ?>>Admin</option>
                                            <option value="Doctor" <?php echo ($edit_user['role'] == 'Doctor') ? 'selected' : ''; ?>>Doctor</option>
                                            <option value="Receptionist" <?php echo ($edit_user['role'] == 'Receptionist') ? 'selected' : ''; ?>>Receptionist</option>
                                        </select><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="full_name">Full Name:</label>
                                        <input type="text" id="full_name" name="full_name" value="<?php echo htmlspecialchars($edit_user['full_name']); ?>"><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="email">Email:</label>
                                        <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($edit_user['email']); ?>"><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="phone_number">Phone Number:</label>
                                        <input type="number" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($edit_user['phone_number']); ?>"><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="password">New Password (leave blank to keep current):</label>
                                        <input type="password" id="password" name="password"><br><br>
                                    </div>

                                    <button type="submit" name="update_user" class="btn">Update User</button>
                                </form>
                            </div>
                            <?php } ?>
                            <?php } ?>

                            <!-- PATIENT TABLE -->
                            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                                <h1>Manage Patients</h1>
                                <table border="1" style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                                    <thead>
                                        <tr>
                                            <th>Patient ID</th>
                                            <th>First Name</th>
                                            <th>Last Name</th>
                                            <th>Date of Birth</th>
                                            <th>Gender</th>
                                            <th>Address</th>
                                            <th>Phone Number</th>
                                            <th>Email</th>
                                            <th>Created At</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        // Fetch all patients from the database
                                        $patients_query = "SELECT * FROM patients";
                                        $patients_result = $conn->query($patients_query);

                                        if ($patients_result->num_rows > 0) {
                                            while ($patient = $patients_result->fetch_assoc()) {
                                                echo '<tr>
                                                        <td>' . htmlspecialchars($patient['patient_id']) . '</td>
                                                        <td>' . htmlspecialchars($patient['first_name']) . '</td>
                                                        <td>' . htmlspecialchars($patient['last_name']) . '</td>
                                                        <td>' . htmlspecialchars($patient['date_of_birth']) . '</td>
                                                        <td>' . htmlspecialchars($patient['gender']) . '</td>
                                                        <td>' . htmlspecialchars($patient['address']) . '</td>
                                                        <td>' . htmlspecialchars($patient['phone_number']) . '</td>
                                                        <td>' . htmlspecialchars($patient['email']) . '</td>
                                                        <td>' . htmlspecialchars($patient['created_at']) . '</td>
                                                        <td>
                                                            <a href="index.php?edit_patient_id=' . urlencode($patient['patient_id']) . '" >Edit</a> 
                                                            <a href="?delete_patient_id=' . urlencode($patient['patient_id']) . '" onclick="return confirm(\'Are you sure you want to delete this patient?\')">Delete</a>
                                                        </td>
                                                    </tr>';
                                            }
                                        } else {
                                            echo '<tr><td colspan="10">No patients found.</td></tr>';
                                        }
                                        ?>
                                    </tbody>
                                </table>
                            </div>

                            <?php if (isset($edit_patient)) { ?>
                            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                                <h1>Edit Patient</h1>
                                <form method="POST" action="">
                                    <input type="hidden" name="edit_patient_id" value="<?php echo $edit_patient['patient_id']; ?>">

                                    <div class="input-group">
                                        <label for="first_name">First Name:</label>
                                        <input type="text" id="first_name" name="first_name" value="<?php echo htmlspecialchars($edit_patient['first_name']); ?>" 
                                            pattern="[A-Za-z\s]+" title="First name can only contain letters and spaces." required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="last_name">Last Name:</label>
                                        <input type="text" id="last_name" name="last_name" value="<?php echo htmlspecialchars($edit_patient['last_name']); ?>"
                                            pattern="[A-Za-z\s]+" title="Last name can only contain letters and spaces." required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="date_of_birth">Date of Birth:</label>
                                        <input type="date" id="date_of_birth" name="date_of_birth" value="<?php echo htmlspecialchars($edit_patient['date_of_birth']); ?>" required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="gender">Gender:</label>
                                        <select id="gender" name="gender" required>
                                            <option value="Male" <?php echo ($edit_patient['gender'] == 'Male') ? 'selected' : ''; ?>>Male</option>
                                            <option value="Female" <?php echo ($edit_patient['gender'] == 'Female') ? 'selected' : ''; ?>>Female</option>
                                            <option value="Other" <?php echo ($edit_patient['gender'] == 'Other') ? 'selected' : ''; ?>>Other</option>
                                        </select><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="address">Address:</label>
                                        <textarea id="address" name="address"><?php echo htmlspecialchars($edit_patient['address']); ?></textarea><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="phone_number">Phone Number:</label>
                                        <input type="tel" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($edit_patient['phone_number']); ?>" pattern="^\+?[0-9]{11}$" title="Phone number must be 10 digits" required><br><br>
                                    </div>

                                    <div class="input-group">
                                        <label for="email">Email:</label>
                                        <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($edit_patient['email']); ?>"
                                            oninput="this.value = this.value.toLowerCase()" required placeholder="Enter a valid email address"><br><br>
                                    </div>

                                    <button type="submit" name="update_patient" class="btn">Update Patient</button>
                                </form>
                            </div>
                        <?php } ?>

                        <!-- APPOINTMENT TABLE -->
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Manage Appointments</h1>
                            <table border="1" style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th>Appointment ID</th>
                                        <th>Patient ID</th>
                                        <th>Doctor ID</th>
                                        <th>Appointment Date</th>
                                        <th>Reason</th>
                                        <th>Status</th>
                                        <th>Created At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    // Fetch all appointments from the database
                                    $appointments_query = "SELECT * FROM appointments";
                                    $appointments_result = $conn->query($appointments_query);

                                    if ($appointments_result->num_rows > 0) {
                                        while ($appointment = $appointments_result->fetch_assoc()) {
                                            echo '<tr>
                                                    <td>' . $appointment['appointment_id'] . '</td>
                                                    <td>' . $appointment['patient_id'] . '</td>
                                                    <td>' . $appointment['doctor_id'] . '</td>
                                                    <td>' . $appointment['appointment_date'] . '</td>
                                                    <td>' . htmlspecialchars($appointment['reason']) . '</td>
                                                    <td>' . $appointment['status'] . '</td>
                                                    <td>' . $appointment['created_at'] . '</td>
                                                    <td>
                                                        <a href="index.php?edit_appointment_id=' . $appointment['appointment_id'] . '">Edit</a> 
                                                        <a href="?delete_appointment_id=' . $appointment['appointment_id'] . '" onclick="return confirm(\'Are you sure you want to delete this appointment?\')">Delete</a>
                                                    </td>
                                                </tr>';
                                        }
                                    } else {
                                        echo '<tr><td colspan="8">No appointments found.</td></tr>';
                                    }
                                    ?>
                                </tbody>
                            </table>
                        </div>

                        <?php if (isset($edit_appointment)) { ?>
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Edit Appointment</h1>
                            <form method="POST" action="">
                                <input type="hidden" name="edit_appointment_id" value="<?php echo $edit_appointment['appointment_id']; ?>">

                                <div class="input-group">
                                    <label for="patient_id">Patient ID:</label>
                                    <input type="text" id="patient_id" name="patient_id" value="<?php echo htmlspecialchars($edit_appointment['patient_id']); ?>" readonly><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="doctor_id">Doctor ID:</label>
                                    <input type="text" id="doctor_id" name="doctor_id" value="<?php echo htmlspecialchars($edit_appointment['doctor_id']); ?>" readonly><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="appointment_date">Appointment Date:</label>
                                    <input type="datetime-local" id="appointment_date" name="appointment_date" value="<?php echo date('Y-m-d\TH:i', strtotime($edit_appointment['appointment_date'])); ?>" required><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="reason">Reason:</label>
                                    <textarea id="reason" name="reason" required><?php echo htmlspecialchars($edit_appointment['reason']); ?></textarea><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="status">Status:</label>
                                    <select id="status" name="status" required>
                                        <option value="Scheduled" <?php echo ($edit_appointment['status'] == 'Scheduled') ? 'selected' : ''; ?>>Scheduled</option>
                                        <option value="Completed" <?php echo ($edit_appointment['status'] == 'Completed') ? 'selected' : ''; ?>>Completed</option>
                                        <option value="Canceled" <?php echo ($edit_appointment['status'] == 'Canceled') ? 'selected' : ''; ?>>Canceled</option>
                                    </select><br><br>
                                </div>

                                <button type="submit" name="update_appointment" class="btn">Update Appointment</button>
                            </form>
                        </div>
                        <?php } ?>

                        <!-- RECORD TABLE -->
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Manage Records</h1>
                            <table border="1" style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                                <thead>
                                    <tr>
                                        <th>Record ID</th>
                                        <th>Patient ID</th>
                                        <th>Doctor ID</th>
                                        <th>Visit Date</th>
                                        <th>Diagnosis</th>
                                        <th>Treatment</th>
                                        <th>Notes</th>
                                        <th>Created At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    // Fetch all records from the database
                                    $records_query = "SELECT * FROM records";
                                    $records_result = $conn->query($records_query);

                                    if ($records_result->num_rows > 0) {
                                        while ($record = $records_result->fetch_assoc()) {
                                            echo '<tr>
                                                    <td>' . $record['record_id'] . '</td>
                                                    <td>' . $record['patient_id'] . '</td>
                                                    <td>' . $record['doctor_id'] . '</td>
                                                    <td>' . $record['visit_date'] . '</td>
                                                    <td>' . htmlspecialchars($record['diagnosis']) . '</td>
                                                    <td>' . htmlspecialchars($record['treatment']) . '</td>
                                                    <td>' . htmlspecialchars($record['notes']) . '</td>
                                                    <td>' . $record['created_at'] . '</td>
                                                    <td>
                                                        <a href="index.php?edit_record_id=' . $record['record_id'] . '">Edit</a> 
                                                        <a href="?delete_record_id=' . $record['record_id'] . '" onclick="return confirm(\'Are you sure you want to delete this record?\')">Delete</a>
                                                    </td>
                                                </tr>';
                                        }
                                    } else {
                                        echo '<tr><td colspan="9">No records found.</td></tr>';
                                    }
                                    ?>
                                </tbody>
                            </table>
                        </div>

                        <?php if (isset($edit_record)) { ?>
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                            <h1>Edit Record</h1>
                            <form method="POST" action="">
                                <input type="hidden" name="edit_record_id" value="<?php echo $edit_record['record_id']; ?>">

                                <div class="input-group">
                                    <label for="patient_id">Patient ID:</label>
                                    <input type="text" id="patient_id" name="patient_id" value="<?php echo htmlspecialchars($edit_record['patient_id']); ?>" readonly><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="doctor_id">Doctor ID:</label>
                                    <input type="text" id="doctor_id" name="doctor_id" value="<?php echo htmlspecialchars($edit_record['doctor_id']); ?>" readonly><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="visit_date">Visit Date:</label>
                                    <input type="datetime-local" id="visit_date" name="visit_date" value="<?php echo date('Y-m-d\TH:i', strtotime($edit_record['visit_date'])); ?>" required><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="diagnosis">Diagnosis:</label>
                                    <textarea id="diagnosis" name="diagnosis" required><?php echo htmlspecialchars($edit_record['diagnosis']); ?></textarea><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="treatment">Treatment:</label>
                                    <textarea id="treatment" name="treatment" required><?php echo htmlspecialchars($edit_record['treatment']); ?></textarea><br><br>
                                </div>

                                <div class="input-group">
                                    <label for="notes">Notes:</label>
                                    <textarea id="notes" name="notes"><?php echo htmlspecialchars($edit_record['notes']); ?></textarea><br><br>
                                </div>

                                <button type="submit" name="update_record" class="btn">Update Record</button>
                            </form>
                        </div>
                        <?php } ?>

                        <!--GENERATE REPORTS-->
                        <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                        <h1>Admin Dashboard - Reports</h1>

                        <form method="POST" action="">
                            
                            <input type="date" id="date_from" name="date_from" required><br><br>
                            <input type="date" id="date_to" name="date_to" required><br>

                            <button type="submit" name="generate_report" class="btn">Generate Report</button>
                        </form>
                        
                        <div style="margin-top: 20px;">
                            <?php if (isset($report_data)) { ?>
                                <h2>Report Results</h2>
                                
                                <!-- Users Table -->
                                <h3>Users</h3>
                                <table border="1" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                                    <thead>
                                        <tr>
                                            <th>User ID</th>
                                            <th>Username</th>
                                            <th>Role</th>
                                            <th>Full Name</th>
                                            <th>Email</th>
                                            <th>Phone Number</th>
                                            <th>Created At</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($report_data['users'] as $user) { ?>
                                            <tr>
                                                <td><?php echo $user['user_id']; ?></td>
                                                <td><?php echo $user['username']; ?></td>
                                                <td><?php echo $user['role']; ?></td>
                                                <td><?php echo $user['full_name']; ?></td>
                                                <td><?php echo $user['email']; ?></td>
                                                <td><?php echo $user['phone_number']; ?></td>
                                                <td><?php echo $user['created_at']; ?></td>
                                            </tr>
                                        <?php } ?>
                                    </tbody>
                                </table>
                                
                                <!-- Patients Table -->
                                <h3>Patients</h3>
                                <table border="1" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                                    <thead>
                                        <tr>
                                            <th>Patient ID</th>
                                            <th>First Name</th>
                                            <th>Last Name</th>
                                            <th>Date of Birth</th>
                                            <th>Gender</th>
                                            <th>Address</th>
                                            <th>Phone Number</th>
                                            <th>Email</th>
                                            <th>Created At</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($report_data['patients'] as $patient) { ?>
                                            <tr>
                                                <td><?php echo $patient['patient_id']; ?></td>
                                                <td><?php echo $patient['first_name']; ?></td>
                                                <td><?php echo $patient['last_name']; ?></td>
                                                <td><?php echo $patient['date_of_birth']; ?></td>
                                                <td><?php echo $patient['gender']; ?></td>
                                                <td><?php echo $patient['address']; ?></td>
                                                <td><?php echo $patient['phone_number']; ?></td>
                                                <td><?php echo $patient['email']; ?></td>
                                                <td><?php echo $patient['created_at']; ?></td>
                                            </tr>
                                        <?php } ?>
                                    </tbody>
                                </table>

                                <!-- Appointments Table -->
                                <h3>Appointments</h3>
                                <table border="1" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                                    <thead>
                                        <tr>
                                            <th>Appointment ID</th>
                                            <th>Patient ID</th>
                                            <th>Doctor ID</th>
                                            <th>Appointment Date</th>
                                            <th>Status</th>
                                            <th>Reason</th>
                                            <th>Created At</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($report_data['appointments'] as $appointment) { ?>
                                            <tr>
                                                <td><?php echo $appointment['appointment_id']; ?></td>
                                                <td><?php echo $appointment['patient_id']; ?></td>
                                                <td><?php echo $appointment['doctor_id']; ?></td>
                                                <td><?php echo $appointment['appointment_date']; ?></td>
                                                <td><?php echo $appointment['status']; ?></td>
                                                <td><?php echo $appointment['reason']; ?></td>
                                                <td><?php echo $appointment['created_at']; ?></td>
                                            </tr>
                                        <?php } ?>
                                    </tbody>
                                </table>

                                <!-- Records Table -->
                                <h3>Records</h3>
                                <table border="1" style="width: 100%; border-collapse: collapse;">
                                    <thead>
                                        <tr>
                                            <th>Record ID</th>
                                            <th>Patient ID</th>
                                            <th>Doctor ID</th>
                                            <th>Visit Date</th>
                                            <th>Diagnosis</th>
                                            <th>Treatment</th>
                                            <th>Notes</th>
                                            <th>Created At</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($report_data['records'] as $record) { ?>
                                            <tr>
                                                <td><?php echo $record['record_id']; ?></td>
                                                <td><?php echo $record['patient_id']; ?></td>
                                                <td><?php echo $record['doctor_id']; ?></td>
                                                <td><?php echo $record['visit_date']; ?></td>
                                                <td><?php echo $record['diagnosis']; ?></td>
                                                <td><?php echo $record['treatment']; ?></td>
                                                <td><?php echo $record['notes']; ?></td>
                                                <td><?php echo $record['created_at']; ?></td>
                                            </tr>
                                        <?php } ?>
                                    </tbody>
                                </table>
                            <?php } ?>
                        </div>
                    </div>

                        <a href="?logout=true" class="btn">Logout</a><br><br><br>
			            <a href="?logout_all=true" class="btn">Logout from All Sessions</a>
                    </div>
                <?php } ?>
        <?php } ?>
    </body>
</html>