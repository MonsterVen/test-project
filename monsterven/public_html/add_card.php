<?php
header('Content-Type: application/json');

// Подключение к базе данных
$servername = "localhost";
$username = "monsterven"; // Ваше имя пользователя базы данных
$password = "MonsterBROsql123%"; // Ваш пароль базы данных
$dbname = "monsterven"; // Имя базы данных

$conn = new mysqli($servername, $username, $password, $dbname);

// Проверяем соединение
if ($conn->connect_error) {
    echo json_encode(["success" => false, "message" => "Ошибка соединения с базой данных"]);
    exit();
}

// Получаем данные из POST-запроса
$name = $_POST['name'] ?? '';
$disc = $_POST['disc'] ?? '';
$tag = $_POST['tag'] ?? '';
$place = $_POST['place'] ?? '';
$img = $_POST['img'] ?? '';

// Проверяем заполненность полей
if (empty($name) || empty($disc) || empty($tag) || empty($place) || empty($img)) {
    echo json_encode(["success" => false, "message" => "Все поля должны быть заполнены."]);
    exit();
}

// Вставляем данные в таблицу card
$sql = "INSERT INTO card (name, disc, tag, place, img) VALUES (?, ?, ?, ?, ?)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("sssss", $name, $disc, $tag, $place, $img);

if ($stmt->execute()) {
    echo json_encode(["success" => true]);
} else {
    echo json_encode(["success" => false, "message" => "Ошибка при добавлении данных: " . $conn->error]);
}

$stmt->close();
$conn->close();
?>