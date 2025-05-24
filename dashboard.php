<?php
session_start();


// HTTP Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com; style-src 'self' https://stackpath.bootstrapcdn.com 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://stackpath.bootstrapcdn.com;");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"); // Uncomment if site is HTTPS only


// Check if the user is logged in, if not then redirect to login page
if (!isset($_SESSION["user_id"])) {
    header("Location: signin.php");
    exit;
}

$username = $_SESSION["username"] ?? 'User'; // Default to 'User' if username somehow not set
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light container">
        <a class="navbar-brand" href="#">My Application</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <span class="navbar-text">
                        Welcome, <?php echo htmlspecialchars($username); ?>!
                    </span>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="logout.php">Logout</a>
                </li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <div class="dashboard-container">
            <h1 class="text-center">User Dashboard</h1>
            <hr>
            <p>This is a protected area. Only logged-in users can see this page.</p>
            <p>Here you might find user-specific information or application features.</p>
            
            <!-- Example Content -->
            <div class="card mt-4">
                <div class="card-body">
                    <h5 class="card-title">Your Profile</h5>
                    <p class="card-text">Some details about your profile could go here.</p>
                    <a href="#" class="btn btn-primary">Edit Profile (Not Implemented)</a>
                </div>
            </div>
             <div class="card mt-3">
                <div class="card-body">
                    <h5 class="card-title">Settings</h5>
                    <p class="card-text">Application settings could be managed here.</p>
                    <a href="#" class="btn btn-secondary">Manage Settings (Not Implemented)</a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
