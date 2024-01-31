<?php

require_once '../src/SHTTP.php';

// Disable exceptions
SHTTP::setExceptionLevel(0);
// Disable certificate validation
SHTTP::$verifCERT = false;
// Call Open Trivia Database. We add an extra header to change default User-Agent header
$resp = json_decode(SHTTP::get('https://opentdb.com/api.php?amount=2&category=30', ['User-Agent: Test/1.0']));
// Print response
print_r($resp);
// Print status codes
printf("Response: <%d:%s>\n", SHTTP::respCode(), SHTTP::respStatus());
