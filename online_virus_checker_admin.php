<?php
/*
MySQL Code:
CREATE DATABASE virus_checker;
USE virus_checker;
CREATE TABLE virus_definitions(malware VARCHAR(256) NOT NULL, signature BYTES(20) NOT NULL);
CREATE TABLE admin_info(username VARCHAR(256) NOT NULL, password VARCHAR(256) NOT NULL);
GRANT ALL ON virus_checker.* TO 'admin'@'localhost' IDENTIFIED BY 'Arb-itary Passwrd';
*/

require_once 'login.php';
$conn = new mysqli($hn,$un,$pw,$db);
if($conn->connect_error)
    die(get_error_message());
$result = NULL;

// Set session to use only cookies and warn users about it.
ini_set('session.use_only_cookies', 1);
ini_set('session.gc_maxlifetime', 60 * 60); // 1 hour session
echo "This site requires cookies for an optimal experience.<br>";

// Log-in for admins
echo <<<_END
<html>
<head>
<title>Online Virus Checker Login</title>
<script>
    function validate(form) {
        fail = validateUsername(form.user_name.value)
        fail += validatePassword(form.pass_word.value)

        if(fail == "") return true
        else { alert(fail); return false }
    }

    function validateUsername(field) {
        return (field == "")?"Username field cannot be empty.\n":""
    }

    function validatePassword(field) {
        return (field == "")?"Password field cannot be empty.\n":""
    }
</script>
</head>

<body>
<table border="0" cellpadding="2" cellspacing="5" bgcolor="#eeeeee">
  <th colspan="2" align="center">Login</th>
<form method='post' action ='online_virus_checker_admin.php'
enctype='multipart/form-data' onsubmit="return validate(this)"><pre>
<tr><td>Username:</td> <td><input type='text' name='user_name'></td></tr>
<tr><td>Password:</td> <td><input type='text' name='pass_word'></td></tr>
<tr><td colspan="2" align="center"><input type='submit' name='login' value='Login'></td></tr>
</pre></form>
</table></body>
</html>
_END;

session_start();
if(isset($_SEESION['check']) &&
    $_SESSION['check'] != hash('ripemd128', $_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT'])) {
    destroy_session_data();
    echo "Please log-in again. :)";
}

function destroy_session_data() {
    $_SESSION = array();
    setcookie(session_name(), '', time() - 2592000, '/');
    session_destroy();
}

session_regenerate_id();

// Directs admins to main page if session is still active.
if(isset($_SESSION['user'])) {
    header("location:online_virus_checker.php");
    die();
}

if(isset($_POST['login']) && isset($_POST['user_name']) && isset($_POST['pass_word'])) {
    log_in_admin($conn);
}

function log_in_admin($conn) {
    $username = mysqli_post_sanitize($conn,'user_name');
    $password = mysqli_post_sanitize($conn,'pass_word');
	if($username === "" || $password === "") {
		echo "Username and password field cannot be empty.";
		return NULL;
    }

	$query = "SELECT password FROM admin_info WHERE username='$username'";
    $result = $conn -> query($query);
	if(mysqli_num_rows($result) < 1) {
        echo "Invalid username/password combination; please try again. :(<br>";
    }
	else {
         // Gets the hash from the $result
        $hash = ($result->fetch_array(MYSQLI_NUM))[0];
		$verify = password_verify($password, $hash);
		if($verify) {
            session_start();
            $_SESSION['user'] = $username;
            $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']);
            $result->close();
            header("location:online_virus_checker.php");
            die();
		}
		else {
			echo "Invalid username/password combination; please try again. :(<br>";	
		}
	}
	$result->close();
}

// Returns a sanitized $_POST string
function mysqli_post_sanitize($conn, $post) { 
	if(get_magic_quotes_gpc()) $post = stripslashes($post);
	return $conn -> real_escape_string(htmlentities($_POST[$post]));
}

function get_error_message() {
	return "Sorry, an error has occured. :(<br>";
}

// Close the MySQL connection
if($result !== NULL)
    $result->close();
$conn->close();
?>