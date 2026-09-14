<?php
$dbc = mysqli_connect('localhost', 'monsterven', 'MonsterBROsql123%', 'monsterven');

// Get all cards instead of just one
$query = "SELECT * FROM card";
$result = mysqli_query($dbc, $query) or die(mysqli_error($dbc));

$cards = array();
while ($row = mysqli_fetch_array($result)) {
    $cards[] = array(
        'id' => $row['id'],
        'name' => $row['name'],
        'disc' => $row['disc'],
        'tag' => $row['tag'],
        'place' => $row['place'],
        'img' => $row['img']
    );
}

http_response_code(200);
header('Content-type: application/json');
echo json_encode($cards);

mysqli_close($dbc);