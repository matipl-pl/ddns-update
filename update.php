<?php
/** EXAMPLE OF USE **/
/** prepare secret parameter:
 * php -r "echo rawurlencode('home.domena.pl:v/q8nVsPx7+sPhX6+N5lcg==') . PHP_EOL;"
 *
 * example run code with secret:
 * curl 'https://127.0.0.1/update.php?domain=home.domena.pl&secret=home.domena.pl%3Av%2Fq8nVsPx7%2BsPhX6%2BN5lcg%3D%3D'
 *
 * if you want to set a specific IP address (ip param):
 * curl 'https://127.0.0.1/update.php?domain=home.domena.pl&ip=8.8.8.8&secret=home.domena.pl%3Av%2Fq8nVsPx7%2BsPhX6%2BN5lcg%3D%3D'
 *
 **/

/** VARIABLES **/
$serverDns = 'your.dns.server.com';

header('Content-Type: text/plain');
update($serverDns, $_GET);

/** PLEASE DO NOT MODIFY THE FUNCTIONS BELOW **/

/**
 * @param string $serverDns
 * @param array $params
 */
function update(string $serverDns, array $params)
{
    $domain = $params['domain'] ?? null;
    $address = $params['address'] ?? null;
    $secret = isset($params['secret']) ? rawurldecode($params['secret']) : null;
    $clientIP = getUserIP();
    $ip = $address ?? $clientIP;

    if (!$domain || !$ip) {
        echo 'Wrong parameters' . PHP_EOL;
        die();
    }
    if (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        echo 'Wrong domain: ' . $domain . PHP_EOL;
        die();
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo 'Wrong IP: ' . $ip . PHP_EOL;
        die();
    }

    echo 'Secret: ' . $secret . PHP_EOL;
    echo 'Domain: ' . $domain . PHP_EOL;

    $actualIP = getActualDomainIP($domain, $serverDns);
    $ip = updateDomain($domain, $secret, $ip, $actualIP, $serverDns);

    echo 'Received IP: ' . $address . PHP_EOL;
    echo 'Client   IP: ' . $clientIP . PHP_EOL;
    echo PHP_EOL;
    echo 'Actual   IP: ' . $actualIP . PHP_EOL;
    echo 'Set      IP: ' . $ip . PHP_EOL;
    die();
}

/**
 * @param string $domain    nazwa domeny, ktorej modyfikujemy wartosc A
 * @param string $secret    klucz do podpisania zadania
 * @param string $ip        adres IP ktory ma byc uzyty w rekordzie A
 * @param string $actualIP  obecny adres IP z rekordu A
 * @param string $serverDns nazwa serwera nazw
 * @return string|null
 */
function updateDomain(string $domain, string $secret, string $ip, string $actualIP, string $serverDns): ?string
{
    if ($ip == $actualIP) {
        return null;
    }

    $nsUpdateParam = $secret ? ' -y hmac-md5:' . $secret : '';
    $process = proc_open(
        'nsupdate' . $nsUpdateParam,
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
        ],
        $pipes,
        NULL,
        NULL
    );
    fwrite($pipes[0], 'server ' . $serverDns . "\n");
    fwrite($pipes[0], 'update delete ' . $domain . ". A\n");
    fwrite($pipes[0], 'update add ' . $domain . '. 2 A ' . $ip . "\n\n");
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]) . PHP_EOL;

    $return = proc_close($process);
    if ($return == 0) {
        return $ip;
    }

    return null;
}

/**
 * @param string $domain    nazwa domeny, ktorej chcemy sprawdzic watosc rekordu A
 * @param string $serverDns nazwa serwera nazw
 * @return string|null
 */
function getActualDomainIP(string $domain, string $serverDns): ?string
{
    $process = proc_open(
        'dig ' . $domain . ' A @' . $serverDns,
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
        ],
        $pipes,
        NULL,
        NULL
    );

    $response = stream_get_contents($pipes[1]);
    preg_match('/IN\tA\t(.*)/', $response, $matches);
    $ip = $matches[1] ?? null;
    proc_close($process);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo 'Wrong IP User: ' . $ip . PHP_EOL;
        die();
    }

    return $ip;
}

/**
 * Sprawdzamy adres IP requestu (IP Uzytkownika)
 *
 * @return string|null
 */
function getUserIP(): ?string
{
    if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
        $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        $_SERVER['HTTP_CLIENT_IP'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
    }
    $client = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote = $_SERVER['REMOTE_ADDR'];

    if (filter_var($client, FILTER_VALIDATE_IP)) {
        $ip = $client;
    } elseif (filter_var($forward, FILTER_VALIDATE_IP)) {
        $ip = $forward;
    } else {
        $ip = $remote;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo 'Wrong IP User: ' . $ip . PHP_EOL;
        die();
    }

    return $ip;
}
