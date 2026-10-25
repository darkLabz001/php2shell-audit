<?php
// Harmless lab landing page. The scanner reads the X-Powered-By header and the
// displayed version to compare the two containers.
declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');
echo "php2shell-audit lab\n";
echo "PHP version: " . PHP_VERSION . "\n";
echo "SAPI: " . PHP_SAPI . "\n";
