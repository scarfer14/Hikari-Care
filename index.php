<?php
session_start();

ini_set('display_errors', 1);
error_reporting(E_ALL);

$host = "localhost";
$user = "u415861906_infosec2235";
$pass = "1nrmG~9]|zkZV>/K";
$db = "u415861906_infosec2235";

$conn=new mysqli($host, $user, $pass, $db);
if ($conn->connect_error){
    echo "Failed to connect to DB".$conn->connect_error;
}


if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();

        $_SESSION['username'] = $row['username'];
            $_SESSION['role'] = $row['role'];

            if ($row['role'] == 'Doctor') {
                // Store doctor ID in the session
                $_SESSION['doctor_id'] = $row['user_id'];
            }

            // After successful login, redirect to index.php
            header("Location: index.php");
            exit();
    } else {
        echo "Invalid username or password.";
    }
}

// redirect to signin.php if the user is not logged in
if (!isset($_SESSION['role'])) {
    // if session is not set, show login form
    $show_login_form = true;
} else {
    // if session is set, show the role-based dashboard
    $show_login_form = false;
}

//will handle logout request
if (isset($_GET['logout'])) {
    session_destroy(); // Destroy the session
    header("Location: index.php"); // Redirect to index.php
    exit();
}


//RECEPTION SECTION
//New Patient
// Function to generate a random Patient ID and check if it exists
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

// Assign the generated Patient ID to a variable
$patientID = generatePatientID($conn);



//appointments
// Fetch the patient IDs and doctor IDs to populate the dropdowns
$patients_query = "SELECT patient_id, first_name, last_name FROM patients";
$patients_result = $conn->query($patients_query);

$doctors_query = "SELECT user_id, full_name FROM users WHERE role = 'Doctor'";
$doctors_result = $conn->query($doctors_query);


// Generate a unique appointment ID (like patient ID)
function generateAppointmentID($conn) {
    do {
        // Generate a random Appointment ID prefixed with 'A'
        $randomID = 'A' . str_pad(rand(1, 99999), 5, '0', STR_PAD_LEFT);

        // Check if the generated Appointment ID already exists in the database
        $query = "SELECT appointment_id FROM appointments WHERE appointment_id = ?";
        $stmt = $conn->prepare($query);
        if ($stmt) {
            $stmt->bind_param("s", $randomID);
            $stmt->execute();
            $stmt->store_result();
        } else {
            die("Database error: " . $conn->error);
        }

    } while ($stmt->num_rows > 0); // Keep generating a new ID if it already exists

    $stmt->close(); // Close the prepared statement
    return $randomID; // Return the unique Appointment ID
}

// Generate and assign the unique Appointment ID
$appointmentID = generateAppointmentID($conn);


//ALL FORMS WILL BE HANDLED HERE
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['form_type'])) {
        $form_type = $_POST['form_type'];

        // Handle New Patient Form Submission
        if ($form_type == "new_patient") {
            $patient_id = $_POST['patient_id'];
            $first_name = $_POST['first_name'];
            $last_name = $_POST['last_name'];
            $dob = $_POST['dob'];
            $gender = $_POST['gender'];
            $address = $_POST['address'];
            $phone = $_POST['phone'];
            $email = $_POST['email'];

            $stmt = $conn->prepare("INSERT INTO patients (patient_id, first_name, last_name, date_of_birth, gender, address, phone_number, email, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("ssssssss", $patient_id, $first_name, $last_name, $dob, $gender, $address, $phone, $email);

            if ($stmt->execute()) {
                echo "New patient record created successfully.";
            } else {
                echo "Error: " . $stmt->error;
            }
            $stmt->close();

        } 
        // Handle Appointment Form Submission
        elseif ($form_type == "new_appointment") {
            $appointment_id = $_POST['appointment_id'];
            $patient_id = $_POST['patient_id'];
            $doctor_id = $_POST['doctor_id'];
            $appointment_date = $_POST['appointment_date'];
            $reason = $_POST['reason'];
            $status = $_POST['status'];

            $stmt = $conn->prepare("INSERT INTO appointments (appointment_id, patient_id, doctor_id, appointment_date, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("ssssss", $appointment_id, $patient_id, $doctor_id, $appointment_date, $reason, $status);

            if ($stmt->execute()) {
                echo "Appointment record created successfully.";
            } else {
                echo "Error: " . $stmt->error;
            }
            $stmt->close();
        }

        // New Record Form Submission (for doctors)
        elseif ($form_type == "new_record") {
            // Get data from POST request
            $patient_id = $_POST['patient_id'];
            $doctor_id = $_SESSION['doctor_id'];  // Get the doctor ID from the session
            $visit_date = $_POST['visit_date'];
            $diagnosis = $_POST['diagnosis'];
            $treatment = $_POST['treatment'];
            $notes = $_POST['notes'];

            // Validate the data
            if (empty($patient_id) || empty($doctor_id) || empty($visit_date) || empty($diagnosis) || empty($treatment) || empty($notes)) {
                echo "<p>All fields are required!</p>";
            } else {
                // Step 1: Verify if the patient_id exists in the patients table
                $query = "SELECT patient_id FROM patients WHERE patient_id = ?";
                $stmt = $conn->prepare($query);
                $stmt->bind_param("s", $patient_id);
                $stmt->execute();
                $stmt->store_result();

                // If no matching patient is found, show an error message
                if ($stmt->num_rows == 0) {
                    echo "<p>Error: The patient ID does not exist.</p>";
                } else {
                    // Step 2: If patient ID exists, insert the record into the records table
                    $stmt = $conn->prepare("INSERT INTO records (patient_id, doctor_id, visit_date, diagnosis, treatment, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
                    $stmt->bind_param("ssssss", $patient_id, $doctor_id, $visit_date, $diagnosis, $treatment, $notes);

                    if ($stmt->execute()) {
                        echo "<p>New record added successfully!</p>";
                    } else {
                        echo "<p>Error: " . $stmt->error . "</p>";
                    }
                }
                $stmt->close();
            }
        }

    }
}


// Check if the form was submitted and the patient_id is provided
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['patient_id'])) {
    $patient_id = $_POST['patient_id']; // Get the patient_id from the form submission

    // Fetch the patient records from the database
    $query = "SELECT visit_date, diagnosis, treatment, notes FROM records WHERE patient_id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $patient_id);
    $stmt->execute();
    $stmt->store_result();

    // Check if records were found
    if ($stmt->num_rows > 0) {
        // Fetch the records
        $stmt->bind_result($visit_date, $diagnosis, $treatment, $notes);
        $records = [];
        while ($stmt->fetch()) {
            $records[] = [
                'visit_date' => $visit_date,
                'diagnosis' => $diagnosis,
                'treatment' => $treatment,
                'notes' => $notes
            ];
        }
    } else {
        $records = []; // No records found for the patient
    }
    $stmt->close();
} else {
    $records = []; // Initialize empty if no search is done yet
}


// Check if the form is submitted
if (isset($_POST['add_user'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $role = $_POST['role'];
    $full_name = $_POST['full_name'];
    $email = $_POST['email'];
    $phone_number = $_POST['phone_number'];

    // Hash the password using bcrypt
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Prepare the SQL query
    $sql = "INSERT INTO users (username, password, role, full_name, email, phone_number) 
            VALUES (?, ?, ?, ?, ?, ?)";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssssi", $username, $hashedPassword, $role, $full_name, $email, $phone_number);

    // Execute the query
    if ($stmt->execute()) {
        echo "User added successfully.";
    } else {
        echo "Error: " . $conn->error;
    }
}

if (isset($_GET['delete_user_id'])) {
    $delete_user_id = $_GET['delete_user_id']; // Get user_id from the URL

    // SQL query to delete the user permanently from the database
    $delete_query = "DELETE FROM users WHERE user_id = ?";
    $stmt = $conn->prepare($delete_query);
    $stmt->bind_param("s", $delete_user_id);

    // Execute the query
    if ($stmt->execute()) {
        echo "<script>alert('User deleted successfully!'); window.location.href = 'index.php';</script>";
    } else {
        echo "<script>alert('Failed to delete user. Please try again.');</script>";
    }

    $stmt->close(); // Close the statement
}

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
    } else {
        echo "<script>alert('User not found.'); window.location.href = 'index.php';</script>";
    }

    $stmt->close();
}


if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_user'])) {
    $user_id = $_POST['edit_user_id'];
    $username = $_POST['username'];
    $role = $_POST['role'];
    $full_name = $_POST['full_name'];
    $email = $_POST['email'];
    $phone_number = $_POST['phone_number'];

    // Update user details in the database
    $update_query = "UPDATE users SET username = ?, role = ?, full_name = ?, email = ?, phone_number = ? WHERE user_id = ?";
    $stmt = $conn->prepare($update_query);
    $stmt->bind_param("ssssss", $username, $role, $full_name, $email, $phone_number, $user_id);

    if ($stmt->execute()) {
        echo "<script>alert('User updated successfully!'); window.location.href = 'index.php';</script>";
    } else {
        echo "<script>alert('Error updating user. Please try again.');</script>";
    }

    $stmt->close();
}

if (isset($_GET['edit_patient_id'])) {
    $patient_id = $_GET['edit_patient_id'];
    $edit_patient_query = "SELECT * FROM patients WHERE patient_id = ?";
    $stmt = $conn->prepare($edit_patient_query);
    $stmt->bind_param("s", $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $edit_patient = $result->fetch_assoc();
    $stmt->close();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_patient'])) {
    $patient_id = $_POST['edit_patient_id'];
    $first_name = $_POST['first_name'];
    $last_name = $_POST['last_name'];
    $date_of_birth = $_POST['date_of_birth'];
    $gender = $_POST['gender'];
    $address = $_POST['address'];
    $phone_number = $_POST['phone_number'];
    $email = $_POST['email'];

    // Update patient details in the database
    $update_query = "UPDATE patients SET first_name = ?, last_name = ?, date_of_birth = ?, gender = ?, address = ?, phone_number = ?, email = ? WHERE patient_id = ?";
    $stmt = $conn->prepare($update_query);
    $stmt->bind_param("ssssssss", $first_name, $last_name, $date_of_birth, $gender, $address, $phone_number, $email, $patient_id);

    if ($stmt->execute()) {
        echo "<script>alert('Patient updated successfully!'); window.location.href = 'index.php';</script>";
    } else {
        echo "<script>alert('Error updating patient. Please try again.');</script>";
    }

    $stmt->close();
}

// Fetch appointment details for editing
if (isset($_GET['edit_appointment_id'])) {
    $appointment_id = $_GET['edit_appointment_id'];
    $edit_appointment_query = "SELECT * FROM appointments WHERE appointment_id = ?";
    $stmt = $conn->prepare($edit_appointment_query);
    $stmt->bind_param("s", $appointment_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $edit_appointment = $result->fetch_assoc();
    $stmt->close();
}

// Update appointment details in the database
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_appointment'])) {
    $appointment_id = $_POST['edit_appointment_id'];
    $patient_id = $_POST['patient_id'];
    $doctor_id = $_POST['doctor_id'];
    $appointment_date = $_POST['appointment_date'];
    $reason = $_POST['reason'];
    $status = $_POST['status'];

    // Update the appointment record
    $update_query = "UPDATE appointments SET patient_id = ?, doctor_id = ?, appointment_date = ?, reason = ?, status = ? WHERE appointment_id = ?";
    $stmt = $conn->prepare($update_query);
    $stmt->bind_param("ssssss", $patient_id, $doctor_id, $appointment_date, $reason, $status, $appointment_id);

    if ($stmt->execute()) {
        echo "<script>alert('Appointment updated successfully!'); window.location.href = 'index.php';</script>";
    } else {
        echo "<script>alert('Error updating appointment. Please try again.');</script>";
    }

    $stmt->close();
}

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

        // Fetch Patients
        $query_patients = "SELECT * FROM patients WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_patients);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['patients'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();

        // Fetch Appointments
        $query_appointments = "SELECT * FROM appointments WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_appointments);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['appointments'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();

        // Fetch Records
        $query_records = "SELECT * FROM records WHERE created_at BETWEEN ? AND ?";
        $stmt = $conn->prepare($query_records);
        $stmt->bind_param("ss", $date_from, $date_to);
        $stmt->execute();
        $report_data['records'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
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
    /* Set fixed height to prevent overlap */
    margin-top: 5px;
    /* Ensure space between label and textarea */
}
    </style>
</head>
<body>

<!-- Show login form if the user is not logged in -->
<?php if ($show_login_form) { ?>
    <nav class="container" id="login">
        <h1 class="form-title">Hikari Care</h1>
        <form id="loginForm" action="index.php" method="POST">
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
            <input type="submit" class="btn" value="Log In" name="login">
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
                        <td><input type="text" id="patient_id" name="patient_id" value="<?php echo $patientID; ?>" /></td>
                        <td><input type="text" name="first_name" required /></td>
                        <td><input type="text" name="last_name" required /></td>
                        <td><input type="date" name="dob" required /></td>
                        <td>
                            <select name="gender" required>
                                <option value="">Select</option>
                                <option value="male">Male</option>
                                <option value="female">Female</option>
                                <option value="other">Other</option>
                            </select>
                        </td>
                        <td><input type="text" name="address" required /></td>
                        <td><input type="tel" name="phone" pattern="[0-9]{10}" required /></td>
                        <td><input type="email" name="email" required /></td>
                    </tr>
                </table>
                    <button type="submit" class="btn">Submit</button>
            </form>
            
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
                        <td><input type="text" id="appointment_id" name="appointment_id" value="<?php echo $appointmentID; ?>" readonly /></td>
                        <td>
                            <select name="patient_id" required>
                                <option value="">Select Patient</option>
                                <?php while ($patient = $patients_result->fetch_assoc()) { ?>
                                    <option value="<?php echo $patient['patient_id']; ?>"><?php echo $patient['first_name'] . ' ' . $patient['last_name']; ?></option>
                                <?php } ?>
                            </select>
                        </td>
                        <td>
                            <select name="doctor_id" required>
                                <option value="">Select Doctor</option>
                                <?php while ($doctor = $doctors_result->fetch_assoc()) { ?>
                                    <option value="<?php echo $doctor['user_id']; ?>"><?php echo $doctor['full_name']; ?></option>
                                <?php } ?>
                            </select>
                        </td>
                        <td><input type="datetime-local" name="appointment_date" required /></td>
                        <td><input type="text" name="reason" /></td>
                        <td>
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

            <!-- Appointments Table -->
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
                            <input type="text" id="patient_id" name="patient_id" value="<?php echo htmlspecialchars($edit_appointment['patient_id']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="doctor_id">Doctor ID:</label>
                            <input type="text" id="doctor_id" name="doctor_id" value="<?php echo htmlspecialchars($edit_appointment['doctor_id']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="appointment_date">Appointment Date:</label>
                            <input type="datetime-local" id="appointment_date" name="appointment_date" value="<?php echo date('Y-m-d\TH:i', strtotime($edit_appointment['appointment_date'])); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="reason">Reason:</label>
                            <textarea id="reason" name="reason"><?php echo htmlspecialchars($edit_appointment['reason']); ?></textarea><br><br>
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

            <br><br><br><a href="?logout=true" class="btn">Logout</a>
        </div>

    <!-- Doctor Section-->
    <?php } elseif ($_SESSION['role'] == 'Doctor') { ?>
        <div id="doctor-section" class="section" style="display:block;">
            <h2>Doctor Dashboard</h2>
            <p>Welcome, Doctor! Here you can view and manage patient records.</p><br><br><br>


                <!-- View Patient Records Section -->
                 <div  style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                <h3>View Records</h3>
                <form method="POST" action="">
                    <br><br><br>
                    <label for="patient_id">Enter Patient ID:</label>
                    <input type="text" id="patient_id" name="patient_id" placeholder="Patient ID" required>
                    <button type="submit" class="btn">Search</button>
                </form>

                <?php if (!empty($records)) : ?>
                    <table style="width: 100%; border: 1px solid #ccc; margin-top: 20px;">
                        <thead>
                            <tr>
                                <th>Visit Date</th>
                                <th>Diagnosis</th>
                                <th>Treatment</th>
                                <th>Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($records as $record) : ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($record['visit_date']); ?></td>
                                    <td><?php echo htmlspecialchars($record['diagnosis']); ?></td>
                                    <td><?php echo htmlspecialchars($record['treatment']); ?></td>
                                    <td><?php echo htmlspecialchars($record['notes']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else : ?>
                    <p>No records found for this patient.</p>
                <?php endif; ?>
                </div>
                <!-- Add New Record Section -->
                <input type="hidden" name="form_type" value="new_record">
                <div id="add-record-section" style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                    <h3>Add New Record</h3><br><br><br>
                    <form method="POST" action="" id="add-record-form">
                        <input type="hidden" name="form_type" value="new_record">

                        <div class="input-group">
                            <label for="patient_id">Patient ID:</label>
                            <input type="text" id="patient_id" name="patient_id" placeholder="Patient ID" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="doctor_id">Doctor ID:</label>
                            <input type="text" id="doctor_id" name="doctor_id" value="<?php echo $_SESSION['doctor_id']; ?>" readonly><br><br>
                        </div>

                        <div class="input-group">
                            <label for="visit_date">Visit Date:</label>
                            <input type="datetime-local" id="visit_date" name="visit_date" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="diagnosis">Diagnosis:</label>
                            <textarea id="diagnosis" name="diagnosis"></textarea><br><br>
                        </div>

                        <div class="input-group">
                            <label for="treatment">Treatment:</label>
                            <textarea id="treatment" name="treatment"></textarea><br><br>
                        </div>

                        <div class="input-group">
                            <label for="notes">Notes:</label>
                            <textarea id="notes" name="notes"></textarea><br><br>
                        </div>

                        <button type="submit" class="btn">Add Record</button>

                    </form>
                </div>

                <!-- Patient Table -->
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
                                            <td>' . $patient['patient_id'] . '</td>
                                            <td>' . $patient['first_name'] . '</td>
                                            <td>' . $patient['last_name'] . '</td>
                                            <td>' . $patient['date_of_birth'] . '</td>
                                            <td>' . $patient['gender'] . '</td>
                                            <td>' . $patient['address'] . '</td>
                                            <td>' . $patient['phone_number'] . '</td>
                                            <td>' . $patient['email'] . '</td>
                                            <td>' . $patient['created_at'] . '</td>
                                            <td>
                                                <a href="index.php?edit_patient_id=' . $patient['patient_id'] . '" >Edit</a> 
                                                <a href="?delete_patient_id=' . $patient['patient_id'] . '" onclick="return confirm(\'Are you sure you want to delete this patient?\')">Delete</a>
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
                            <input type="text" id="first_name" name="first_name" value="<?php echo htmlspecialchars($edit_patient['first_name']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="last_name">Last Name:</label>
                            <input type="text" id="last_name" name="last_name" value="<?php echo htmlspecialchars($edit_patient['last_name']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="date_of_birth">Date of Birth:</label>
                            <input type="date" id="date_of_birth" name="date_of_birth" value="<?php echo $edit_patient['date_of_birth']; ?>" required><br><br>
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
                            <input type="text" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($edit_patient['phone_number']); ?>"><br><br>
                        </div>

                        <div class="input-group">
                            <label for="email">Email:</label>
                            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($edit_patient['email']); ?>"><br><br>
                        </div>
                        
                        <button type="submit" name="update_patient" class="btn">Update Patient</button>
                    </form>
                </div>
                <?php } ?>
                

            <br><br><br><br><br><a href="?logout=true" class="btn">Logout</a>
        </div>

    <!-- Admin Section-->
    <?php } elseif ($_SESSION['role'] == 'Admin') { ?>
        <div id="admin-section" class="section" style="display:block;">
            <h2>Admin Dashboard</h2>
            <p>Welcome, Admin! Here you can manage system settings and accesses.</p>

            <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                <h1>Add User to Database</h1>
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


            <!-- User Table -->
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

                    <button type="submit" name="update_user" class="btn">Update User</button>
                </form>
            </div>
            <?php } ?>
        
            
                <!-- Patient Table -->
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
                                            <td>' . $patient['patient_id'] . '</td>
                                            <td>' . $patient['first_name'] . '</td>
                                            <td>' . $patient['last_name'] . '</td>
                                            <td>' . $patient['date_of_birth'] . '</td>
                                            <td>' . $patient['gender'] . '</td>
                                            <td>' . $patient['address'] . '</td>
                                            <td>' . $patient['phone_number'] . '</td>
                                            <td>' . $patient['email'] . '</td>
                                            <td>' . $patient['created_at'] . '</td>
                                            <td>
                                                <a href="index.php?edit_patient_id=' . $patient['patient_id'] . '" >Edit</a> 
                                                <a href="?delete_patient_id=' . $patient['patient_id'] . '" onclick="return confirm(\'Are you sure you want to delete this patient?\')">Delete</a>
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
                            <input type="text" id="first_name" name="first_name" value="<?php echo htmlspecialchars($edit_patient['first_name']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="last_name">Last Name:</label>
                            <input type="text" id="last_name" name="last_name" value="<?php echo htmlspecialchars($edit_patient['last_name']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="date_of_birth">Date of Birth:</label>
                            <input type="date" id="date_of_birth" name="date_of_birth" value="<?php echo $edit_patient['date_of_birth']; ?>" required><br><br>
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
                            <input type="text" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($edit_patient['phone_number']); ?>"><br><br>
                        </div>

                        <div class="input-group">
                            <label for="email">Email:</label>
                            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($edit_patient['email']); ?>"><br><br>
                        </div>

                        <button type="submit" name="update_patient" class="btn">Update Patient</button>
                    </form>
                </div>
                <?php } ?>

                <!-- Appointments Table -->
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
                            <input type="text" id="patient_id" name="patient_id" value="<?php echo htmlspecialchars($edit_appointment['patient_id']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="doctor_id">Doctor ID:</label>
                            <input type="text" id="doctor_id" name="doctor_id" value="<?php echo htmlspecialchars($edit_appointment['doctor_id']); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="appointment_date">Appointment Date:</label>
                            <input type="datetime-local" id="appointment_date" name="appointment_date" value="<?php echo date('Y-m-d\TH:i', strtotime($edit_appointment['appointment_date'])); ?>" required><br><br>
                        </div>

                        <div class="input-group">
                            <label for="reason">Reason:</label>
                            <textarea id="reason" name="reason"><?php echo htmlspecialchars($edit_appointment['reason']); ?></textarea><br><br>
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


                <!--GENERATE REPORTS-->
                <div style="background: #fff; width: auto; padding: 1rem; margin: 50px auto; border-radius: 10px; box-shadow: 0 20px 35px rgba(0, 0, 1, 0.9);">
                <h1>Admin Dashboard - Reports</h1>

                <form method="POST" action="">
                    <label for="date_from">From:</label>
                    <input type="date" id="date_from" name="date_from" required>
                    
                    <label for="date_to">To:</label>
                    <input type="date" id="date_to" name="date_to" required>

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




            <a href="?logout=true" class="btn">Logout</a>
        </div>
    <?php } ?>
<?php } ?>



</body>
</html>


