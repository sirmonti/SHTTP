<?php

require_once '../src/SHTTP.php';

try {
    // Fire exception on any error
    SHTTP::setExceptionLevel(2);
    // Set the authorization and contect accept headers
    SHTTP::setExtraheaders(['Authorization: Bearer TestToken', 'Accept: application/json']);
    // Call REST test service
    $resp = json_decode(SHTTP::get('https://reqbin.com/echo/get/json'));
    print_r($resp);
} catch (Exception $e) {
    // Print error, if any
    printf("Error: <%d:%s>\n", $e->getCode(), $e->getMessage());
}

