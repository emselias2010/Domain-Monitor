<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";

session_unset();
session_destroy();

 echo json_encode(["success" => true]);
