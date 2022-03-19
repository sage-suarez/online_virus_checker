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

echo <<<_END
<html>
<head><title>Online Virus Checker</title></head>
<body>
<table border="0" cellpadding="2" cellspacing="5" bgcolor="#eeeeee">
  <th colspan="2" align="center">Online Virus Checker</th>

<form method='post' action ='online_virus_checker.php' enctype='multipart/form-data'><pre>
<tr><td>Select Readable File to Scan for Virus:</td> <td><input type='file' name='file_upload' size='10'></td></tr>
<tr><td colspan="2" align="center"><input type='submit' name='check_file' value='Check File'></td></tr>
</pre></form>
</table></body>
_END;

session_start();
if(isset($_SEESION['check']) &&
    $_SESSION['check'] != hash('ripemd128', $_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT'])) {
    destroy_session_data();
    echo "An error has occured. :(";
}

function destroy_session_data() {
  $_SESSION = array();
  setcookie(session_name(), '', time() - 2592000, '/');
  session_destroy();
}

session_regenerate_id();

if(isset($_SESSION['user']))
{
  echo <<<_END
<head>
<script>
function validate(form) {
  fail = validateMalwareName(form.malware_name.value) {

  if(fail == "") return true
  else { alert(fail); return false }
}

function validateMalwareName(field) {
  if(field == "")
    return "Username field cannot be empty.\n"
  else if((/[^a-zA-Z0-9]/.test(field))
    return "Only a-z, A-Z, or 0-9 characters are allowed for malware names.\n"
  else return ""
}
</script>
</head>

<body>
<table border="0" cellpadding="2" cellspacing="5" bgcolor="#eeeeee">
  <th colspan="2" align="center">Upload Malware to Database</th>

<form method='post' action ='online_virus_checker.php' 
enctype='multipart/form-data' onsubmit="return validate(this)"><pre>
<tr><td>Select File to Add to Database:</td> <td><input type='file' name='malware_upload' size='10'></td></tr>
<tr><td>Name of the Malware:</td> <td><input type='text' name='malware_name'><td></tr>
<tr><td colspan="2" align="center"><input type='submit' name='add_malware' value='Upload Malware'></td></tr>
</pre></form>
</table></body>
</html>
_END;
}
else echo "</html>";

if(isset($_FILES['file_upload']) && isset($_POST['check_file'])) {
  //Any file type should be accepted when checking for malware
  //$accepted = FALSE;
  //if($_FILES['file_upload']['type'] === 'text/plain')
    $accepted = TRUE;
  if($accepted) {
    $is_malware = contains_malware($conn);
    if($is_malware)
      echo "<font color=red size=10>Virus checker detects malware in your file. :(</font><br>";
    else if(!$is_malware)
      echo "<font color=green size=10>Virus checker detects no malware in your file. :)</font><br>";
    else
      echo "<font size=5>Unable to check the file.</font><br>";
  }
  else
    echo "Wrong file type; can only currently support text files.<br>";
}

if(isset($_FILES['malware_upload']) && isset($_POST['add_malware'])) {
  add_malware($conn);
}

function contains_malware($conn) {
  $file_name = strtolower(preg_replace("[^A-Za-z0-9.]", "", htmlentities($_FILES['file_upload']['name'])));
  if(!$file_name) {
    echo "Must provide a file to check.<br>";
    return NULL;
  }
  $fh = fopen($file_name, 'rb');
  $file_size = filesize($file_name);
  $file_content = $conn -> real_escape_string(htmlentities(fread($fh, $file_size)));
  fclose($fh);

  $query = "SELECT signature FROM virus_definitions";
  $result = $conn->query($query);
  $rows = mysqli_num_rows($result);
  for($i = 0; $i < $rows; $i++) {
    $result->data_seek($i);
    $signature = ($result->fetch_array(MYSQLI_NUM))[0];

    // If the file contents contains one of the signatures
    // in the database, flag the file as infected
    if(strpos($file_content, $signature) !== FALSE) {
      $result -> close();
      return TRUE;
    }
  }
  $result -> close();
  return FALSE;
}

function add_malware($conn) {
  $malware_name = mysqli_post_sanitize($conn,'malware_name');
  if(!validateMalwareName($malware_name)) {
    return NULL;
  }

  $file_name = strtolower(preg_replace("[^A-Za-z0-9.]", "", htmlentities($_FILES['malware_upload']['name'])));
  if(!$file_name) {
    echo "Must provide a file to upload.<br>";
    return NULL;
  }

  $fh = fopen($file_name, 'rb');
  $file_size = filesize($file_name);
  $file_content = $conn -> real_escape_string(htmlentities(fread($fh, $file_size)));
  fclose($fh);

  $signature = get_file_signature($file_content, $file_size);

  $stmt = $conn->prepare('INSERT INTO virus_definitions VALUES(?,?)');
  $stmt->bind_param('ss',$malware_name,$signature);
  $stmt->execute();
  $stmt->close();
  echo "Malware file uploaded to database.<br>";
}

// Gets the file signature in the middle of a given file content
function get_file_signature($file_content, $file_length) {
    return substr($file_content, 0, 20);
}

// Checks if the inputted name for the malware is not empty
// and contains only English letters and digits
function validateMalwareName($malware_name) {
  if($malware_name === "") {
    echo "Malware name cannot be empty<br>";
    return FALSE;
  }
  else if(preg_match('/[^a-z0-9]/i', $malware_name)) {
    echo "Only a-z, A-Z, or 0-9 characters are allowed for malware names.<br>";
    return FALSE;
  }
  else
    return TRUE;
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
if($result != NULL)
  $result->close();
$conn->close();
?>