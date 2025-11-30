<?php
session_start();

$CLIENT_ID     = '930339744944-53ikbg8gsjfsbp5or46esnkt7gkmu7a1.apps.googleusercontent.com';
$CLIENT_SECRET = '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';
$REDIRECT_URI  = 'https://68c836c45881f.clouduz.ru/google_callback.php';

if (!isset($_GET['code'])) {
    die('Xato: code parametri yo‘q. <a href="/">Bosh sahifa</a>');
}

$token_url = 'https://oauth2.googleapis.com/token';
$data = [
    'code'          => $_GET['code'],
    'client_id'     => $CLIENT_ID,
    'client_secret' => $CLIENT_SECRET,
    'redirect_uri'  => $REDIRECT_URI,
    'grant_type'    => 'authorization_code'
];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $token_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$response = curl_exec($ch);
curl_close($ch);

$token = json_decode($response, true);

if (isset($token['error'])) {
    die('Token xatosi: ' . $token['error_description']);
}

$userinfo = file_get_contents('https://www.googleapis.com/oauth2/v3/userinfo?access_token=' . $token['access_token']);
$user = json_decode($userinfo, true);

$_SESSION['user'] = [
    'name'  => $user['name'] ?? 'No name',
    'email' => $user['email'] ?? '',
    'photo' => $user['picture'] ?? ''
];

header('Location: /');
exit;
