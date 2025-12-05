<?php
// Brute-Force Test Endpoint (c) J~Net 2025

$logfile=__DIR__.'/brute-log.txt';
$valid_user='administrator';
$valid_pass='1234';
$delay_ms=200;

function msleep($ms){
    usleep($ms*1000);
}

$attempt='';
$status='';

if($_SERVER['REQUEST_METHOD']==='POST'){
    $username=preg_replace('/[^a-zA-Z0-9_\-]/','',$_POST['username']??'');
    $password=preg_replace('/[^a-zA-Z0-9_\-]/','',$_POST['password']??'');

    $attempt="Attempt user=$username pass=$password";
    msleep($delay_ms);

    if($username===$valid_user && $password===$valid_pass){
        $status='SUCCESS';
    }else{
        $status='FAIL';
    }

    file_put_contents($logfile,date('Y-m-d H:i:s')." $attempt => $status\n",FILE_APPEND);
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Brute Test</title>
<style>
body{background:#111;color:#eee;font-family:monospace;padding:20px;}
input{background:#222;color:#eee;border:1px solid #333;padding:6px;}
button{background:#333;color:#eee;border:1px solid #444;padding:6px;cursor:pointer;}
button:hover{background:#444;}
#status{margin-top:10px;padding:10px;background:#222;border:1px solid #333;}
</style>
</head>
<body>
<h3>Brute Force Test Endpoint</h3>

<form method="post">
    <div>Username:<br><input name="username"></div>
    <div>Password:<br><input name="password" type="password"></div>
    <button type="submit">Submit</button>
</form>

<div id="status">
<?php
if($attempt!==''){
    echo htmlspecialchars("$attempt => $status");
}else{
    echo "Awaiting input...";
}
?>
</div>

</body>
</html>

