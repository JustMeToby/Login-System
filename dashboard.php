<?php
/**
 * User dashboard page.
 *
 * This script displays the main dashboard for logged-in users.
 * It requires login and shows user-specific information and navigation.
 */
require_once 'src/bootstrap.php'; // Defines $authController, $user, $security

// Require login. If not logged in, will redirect to signin.php
$authController->requireLogin();

// Get username for display
$username = $authController->getLoggedInUsername();
$usernameDisplay = $username ? $security->escapeHTML($username) : 'User';

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
        <a class="navbar-brand" href="<?php echo $authController->buildUrl(PAGE_DASHBOARD); ?>">My Application</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <span class="navbar-text">
                        Welcome, <?php echo $usernameDisplay; ?>!
                    </span>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo $authController->buildUrl(PAGE_LOGOUT); ?>">Logout</a>
                </li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <div class="dashboard-container">
            <?php display_flash_messages('success', 'success'); ?>
            <h1 class="text-center">User Dashboard</h1>
            <hr>
            <p>This is a protected area. Only logged-in users can see this page.</p>
            <p>Here you might find user-specific information or application features.</p>
            
            <div class="card mt-4">
                <div class="card-body">
                    <h5 class="card-title">Your Profile</h5>
                    <p class="card-text">Some details about your profile could go here.</p>
                    <a href="#" class="btn btn-primary disabled">Edit Profile (Not Implemented)</a>
                </div>
            </div>
             <div class="card mt-3">
                <div class="card-body">
                    <h5 class="card-title">Settings</h5>
                    <p class="card-text">Application settings could be managed here.</p>
                    <a href="#" class="btn btn-secondary disabled">Manage Settings (Not Implemented)</a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
