<?php
//$page = str_getcsv(file_get_contents('/proc/self/cmdline'), "\0")[4];
//include $page;

$root = str_getcsv(file_get_contents('/proc/self/cmdline'), "\0")[4];
$script = str_replace('..', '', urldecode($_SERVER['SCRIPT_NAME'])); // safety
header('HTTP/1.1 200 OK');
header('Content-type: '); // disable Content-Type
if ( is_file($root . $script) )
	echo file_get_contents($root . $script);
else
	echo file_get_contents($root . "/index.html");

foreach($_POST as $par=>$val)
	error_log( "\x1b[31m" . "$par: $val" . "\x1b[0m" );
?>