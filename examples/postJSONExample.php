<?php

require_once '../src/SHTTP.php';

try {
    // Fire exception on any error
    SHTTP::setExceptionLevel(2);

    // Enable certificate validation
    SHTTP::$verifCERT = true;

    // Set the authorization header
    SHTTP::setExtraheaders(['Authorization: Bearer TestToken']);
    // Set data
    $data = [
        'name' => 'John',
        'surname' => 'Smith',
        'email' => 'john.smith@example.com'
    ];
    // Call REST test service
    $resp = json_decode(SHTTP::postJSON('https://reqbin.com/echo/post/json', $data));
    print_r($resp);
} catch (Exception $e) {
    // Print error, if any
    printf("Error: <%d:%s>\n", $e->getCode(), $e->getMessage());
}

