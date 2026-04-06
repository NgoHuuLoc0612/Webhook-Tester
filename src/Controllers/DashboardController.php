<?php
declare(strict_types=1);

namespace App\Controllers;

class DashboardController
{
    public function index(): void
    {
        header('Content-Type: text/html; charset=utf-8');
        require_once ROOT_PATH . '/public/app.html';
    }
}
