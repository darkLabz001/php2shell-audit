<?php
// A normal application file. Must not be flagged.
function render_avatar(string $name): string
{
    return '<img alt="' . htmlspecialchars($name) . '">';
}
