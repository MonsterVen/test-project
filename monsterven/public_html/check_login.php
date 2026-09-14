<?php
// Подключение к базе данных
$servername = "localhost";
$username = "monsterven"; // Ваше имя пользователя базы данных
$password = "MonsterBROsql123%"; // Ваш пароль базы данных
$dbname = "monsterven"; // Имя базы данных

$conn = new mysqli($servername, $username, $password, $dbname);

// Проверяем соединение
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Получаем данные из формы
$user = $_POST['username'];
$pass = $_POST['password'];

// Проверяем наличие пользователя в таблице admins
$sql = "SELECT * FROM admins WHERE username = ? AND password = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss", $user, $pass);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    // Успешная авторизация
    header("Location: adminpage.html");
    exit();
} else {
    // Ошибка авторизации
    $error = "Ошибка входа! Неправильный логин или пароль.";
    header("Location: profile.html?error=" . urlencode($error));
    exit();
}

$stmt->close();
$conn->close();
?>