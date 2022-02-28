<!DOCTYPE html>
<html lang="en">
<head>
  <title>New User</title>
</head>
<body>
  <div class="container">

<?php
## - https://stackoverflow.com/questions/5647461/how-do-i-send-a-post-request-with-php
## - Simple function to post and return JSON
function httpPost($url, $data)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_POST, 1);
    $response = curl_exec($ch);
    curl_close($ch);
    $json_response = json_decode($response, true);
    return $json_response;
}

// API access
$api_ip = '127.0.0.1';
$api_port = '2302';
$api_path = 'v1/account/';

// Creating a new user
$fields = ['action' => 'add', 'user' => 'randus', 'domain' => 'randomdomain.example.com', 'pass' => 'SuperSecretPass', 'email' => 'random@random.com', 'package' => 1, 'inode' => 0, 'limit_nproc' => 40, 'limit_nofile' => 150, 'server_ips' => '34.254.187.152'];

$api_uri = 'https://'.$api_ip.':'.$api_port.'/'.$api_path;
$output = httpPost($api_uri, $fields);

echo '<textarea class="form-control">' . json_encode($output) . '</textarea>';

?>

  </div>
</body>
</html>
