<?php

declare(strict_types=1);

/**
 * @package SHTTP
 */
use Composer\Script\Event;
use Symfony\Component\Console\Output\ConsoleOutput;
use Psr\Http\Message\ResponseInterface;
use Nyholm\Psr7\Response as NResponse;
use GuzzleHttp\Psr7\Response as GResponse;
use HttpSoft\Message\Response as HResponse;
use HttpSoft\Message\StreamFactory as HStream;
use Laminas\Diactoros\Response as LResponse;
use Laminas\Diactoros\StreamFactory as LStream;
use Slim\Psr7\Header as SHeader;
use Slim\Psr7\Headers as SHeaders;
use Slim\Psr7\Response as SResponse;
use Slim\Psr7\Stream as SSTream;

/**
 * Wrapper class around file_get_contents function. This class is not intended
 * to compete with full featured network frameworks, as Guzzle or Swoole, but
 * to provide a simple and convenient solution to use web services or access
 * web resources
 * 
 * This class provides a set of static methods that can be called without creating any object.
 * 
 * @see https://github.com/sirmonti/shttp/ SHTTP github project
 * 
 * @author Francisco Monteagudo <francisco@monteagudo.net>
 * @version 8.0.0
 * @license https://opensource.org/licenses/MIT (MIT License)
 * @copyright (c) 2024, Francisco Monteagudo
  A ver */
class SHTTP {

    /**
     * Enable/Disable certificate verification on https connections.
     * 
     * When connecting to a https site, the program verify if the
     * certificate is valid and fires an error if not. Disabling certificate validation
     * you can prevent this error and connect to sites with faulty certificate.
     * You can edit this value to change default value.
     * 
     * @var bool
     */
    static public bool $verifCERT = true;

    /**
     * If request returns a redirection, it must be followed.
     * 
     * @var bool
     */
    static public bool $followRedirs = true;

    /**
     * On the request command, send the full URI instead the path.
     * 
     * For example, instead send "GET /test.html HTTP/1.1" command to the server,
     * script will send "GET http://www.example.com/test.html HTTP/1.1".
     * Include full URI breaks standard, but is neccesary if connect to a proxy.
     * 
     * @var bool
     */
    static public bool $reqFullURI = false;

    /**
     * How many redirections must be followed before a "Many redirections"
     * error must be fired
     * 
     * @var int
     */
    static public int $maxfollows = 20;

    /**
     * Connection timeout. Connection closes if exceds timeout without
     * response. Default value is ten seconds.
     * 
     * @var float
     */
    static public float $timeout = 10.0;

    /**
     * Exception level. You can edit this value to change default value
     * 
     * Expected values:
     * 
     * - 0: No exceptions
     * - 1: Exception only on network errors or invalid arguments
     * - 2: Exception on HTTP errors (4XX and 5XX errors) too
     * 
     * @var int
     */
    static private int $exceptlevel = 1;
    
    /** @ignore */
    private const USERAGENT = 'simpleHTTP/8.0';

    /** @ignore */
    private const DEFHEADER = ['User-Agent: ' . self::USERAGENT];

    /** @ignore */
    private const RESPPACKAGES=[
        'httpsoft/http-message'=>'HttpSoft\Message\Response',
        'nyholm/psr7'=>'Nyholm\Psr7\Response',
        'guzzlehttp/psr7'=>'GuzzleHttp\Psr7\Response',
        'laminas/laminas-diactoros'=>'Laminas\Diactoros\Response',
        'slim/psr7'=>'Slim\Psr7\Response'
    ];

    /** @ignore */
    static private array $extraheaders = [];

    /** @ignore */
    static private string $protversion = '';

    /** @ignore */
    static private int $respcode = 0;

    /** @ignore */
    static private string $respstatus = '';

    /** @ignore */
    static private string $respmime = '';

    /** @ignore */
    static private array $respheaders = [];

    /** @ignore */
    static private string $respbody = '';

    /** @ignore */
    static private string $url = '';

    /** @ignore */
    static private string $method = '';

    /** @ignore */
    static private string $hostheader = '';

    /** @ignore */
    static private array $sendheaders = [];

    /** @ignore */
    static private array $opts = [];

    /** @ignore */
    static private string $body = '';

    /** @ignore */
    static private array $certChain = [];

    /** @ignore */
    static private string $localCert = '';

    /** @ignore */
    static private string $localKey = '';

    /** @ignore */
    static private string $passphrase = '';

    /** @ignore */
    static private string $proxy = '';

    /** @ignore */
    static private function mergeHeaders(array $headers) {
        self::$sendheaders = [];
        $noms = ['content-length' => true];
        self::$hostheader = '';
        foreach([$headers,self::$extraheaders,self::DEFHEADER] as $hdrs) {
            foreach ($hdrs as $head) {
                $key = strtolower(strstr($head, ':', true));
                if (!isset($noms[$key])) {
                    $noms[$key] = true;
                    self::$sendheaders[] = $head;
                    if($key=='host') self::$hostheader = trim(substr(strstr($head,':'),1));
                }
            }
        }
    }

    /** @ignore */
    static private function buildopts(): void {
        if (!filter_var(self::$url, FILTER_VALIDATE_URL)) {
            self::$respcode = -2;
            self::$respstatus = _('Invalid URL');
            throw new Exception;
        }
        $info = parse_url(self::$url);
        if (strtolower(substr($info['scheme'], 0, 4)) != 'http') {
            self::$respcode = -1;
            self::$respstatus = _('Invalid scheme. This class only supports http and https connections');
            throw new Exception;
        }
        if(self::$hostheader=='') {
            $host = $info['host'];
            self::$sendheaders[] = 'Host: ' . $host;
        } else {
            $host = self::$hostheader;
        }
        self::$opts = [
            'http' => [
                'ignore_errors' => true,
                'request_fulluri' => self::$reqFullURI,
                'timeout' => self::$timeout,
                'follow_location' => self::$followRedirs ? 1:0,
                'max_redirects' => self::$maxfollows,
                'method' => self::$method
            ]
        ];
        if (self::$body != '') {
            self::$sendheaders[] = 'Content-Length: ' . strlen(self::$body);
            self::$opts['http']['content'] = self::$body;
        }
        self::$opts['http']['header'] = self::$sendheaders;
        if(self::$proxy!='') {
            self::$opts['http']['proxy']=self::$proxy;
        }
        if (strtolower($info['scheme']) == 'https') {
            if (self::$verifCERT) {
                self::$opts['ssl'] = [
                    'SNI_enabled' => true,
                    'peer_name' => $host,
                    'capture_peer_cert_chain' => true
                ];
            } else {
                self::$opts['ssl'] = [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'capture_peer_cert_chain' => true
                ];
            }
            if (self::$localCert != '') {
                self::$opts['ssl']['local_cert'] = self::$localCert;
            }
            if (self::$localKey != '') {
                self::$opts['ssl']['local_pk'] = self::$localKey;
            }
            if (self::$passphrase != '') {
                self::$opts['ssl']['passphrase'] = self::$passphrase;
            }
        }
    }

    /** @ignore */
    static private function buildResponseHeaders(array $headers) {
        self::$respheaders = [];
        foreach ($headers as $head) {
            $pos = strpos($head, ':');
            if ($pos > 0) {
                [$cab, $val] = explode(':', $head, 2);
                $cab = strtolower(trim($cab));
                $val = trim($val);
                if (isset(self::$respheaders[$cab])) {
                    if (is_array(self::$respheaders[$cab]))
                        self::$respheaders[$cab][] = $val;
                    else
                        self::$respheaders[$cab] = [self::$respheaders[$cab], $val];
                } else {
                    self::$respheaders[$cab] = $val;
                }
                if (strtolower($cab) == 'content-type') {
                    self::$respmime = trim(substr($head, 14));
                }
            }
        }
    }

    /** @ignore */
    static private function execHTTP() {
        self::$respcode = 0;
        self::$protversion = '';
        self::$respstatus = '';
        self::$respmime = '';
        self::$respheaders = [];
        self::$respbody = '';
        self::$certChain = [];
        try {
            if (count(self::$sendheaders) == 0) {
                self::$sendheaders = self::DEFHEADER;
            }
            self::buildopts();
            $ctx = stream_context_create(self::$opts);
            $data = (string) @file_get_contents(self::$url, false, $ctx);
            self::$respbody = $data;
            $opts = stream_context_get_options($ctx);
            if (isset($opts['ssl']['peer_certificate_chain'])) {
                self::$certChain = $opts['ssl']['peer_certificate_chain'];
            }
            if (count((array) @$http_response_header) == 0) {
                self::$respcode = -3;
                self::$respstatus = _('Network error');
                throw new Exception();
            }
            $status = array_shift($http_response_header);
            if (!preg_match('/^HTTP\/([0-9]+\.[0-9]+)\ ([0-9]{3})\ (.+)$/', $status, $resp)) {
                self::$respcode = -3;
                self::$respstatus = _('Network error');
                throw new Exception();
            }
            self::buildResponseHeaders($http_response_header);
            self::$protversion = (string) $resp[1];
            self::$respcode = (int) $resp[2];
            self::$respstatus = (string) $resp[3];
            if ((self::$respcode >= 400) && (self::$exceptlevel == 2))
                throw new Exception();
            return $data;
        } catch (Exception $e) {
            if ((self::$exceptlevel == 2) && (self::$respcode >= 400)) {
                throw new RuntimeException(self::$respstatus, self::$respcode);
            }
            if (self::$exceptlevel > 0) {
                if (self::$respcode == -3) {
                    throw new RuntimeException(self::$respstatus, self::$respcode);
                } else {
                    throw new InvalidArgumentException(self::$respstatus, self::$respcode);
                }
            }
        }
        return self::$respbody;
    }

    /**
     * Set exception level
     * 
     * This method configures the use of exceptions on an error. There are three exception levels
     * 
     * - 0: No exceptions fired. Operations results are returned in httpcode and httpstatus
     * - 1: Exceptions only on network errors or bad formed URLs. HTTP errors don't fire exceptions
     * - 2: All errors fire an exception.
     * 
     * @param int $level Exception level
     */
    static function setExceptionLevel(int $level): void {
        if (($level >= 0) && ($level <= 2))
            self::$exceptlevel = $level;
    }

    /**
     * Get the configured exception level
     * 
     * @return int Configured exception level
     */
    static function getExceptionLevel(): int {
        return self::$exceptlevel;
    }

    /**
     * Set the proxy server
     * 
     * You provide the host name or IP address and port
     * 
     * @param string $host Proxy host
     * @param int $port Proxy port
     * @return bool Proxy has been set OK
     */
    static function setProxy(string $host='',int $port=8080): bool {
        if($host=='') {
            self::$proxy='';
            return true;
        }
        if($port==0) return false;
        if((filter_var($host,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4|FILTER_FLAG_IPV6))||
           (filter_vars($host,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME))) {
            self::$proxy='tcp://'.$host.':'.$port;
            return true;
        }
        return false;
    }

    /**
     * Get the proxy parameters
     * 
     * @param string $host Filled with proxy host name or IP
     * @param int $port Filled with proxy port
     */
    static function getProxy(string &$host, int &$port) {
        $host='';
        $port=0;
        if(self::$proxy=='') return;
        if(!preg_match('/^tcp\:\/\/(.+)\:([0-9]+)$/',self::$proxy,$resp)) return;
        $host=$resp[1];
        $port=(int)$resp[2];
    }

    /**
     * Define a set of extra headers to be attached to following requests
     * 
     * @param array<int,string> $headers Extra headers to set
     */
    static function setExtraHeaders(array $headers = []) {
        self::$extraheaders = $headers;
        self::mergeHeaders([]);
    }

    /**
     * Get the extra headers, if any
     * 
     * @return array<int,string> Configured extra headers
     */
    static function getExtraHeaders(): array {
        return self::$extraheaders;
    }

    /**
     * Get the headers that has been sent on last request
     * 
     * If you call this method before any request, it will
     * return default headers.
     * 
     * @return array Header sent on last request
     */
    static function getSendHeaders(): array {
        if (count(self::$sendheaders) == 0)
            return self::DEFHEADER;
        return self::$sendheaders;
    }

    /**
     * Get the body that has been sent on last request
     * 
     * If you call this method before any request, it will
     * return an empty string.
     * 
     * @return string Body sent on last request
     */
    static function getSendBody(): string {
        return self::$body;
    }

    /**
     * Get the peer certificate from the visited site
     * 
     * When connecting to a https site, the certificate chain for the remote
     * site is retrieved, allowing extra validations. This method returns the
     * certificate of the visited site. The certificate can be proccesed with
     * the openssl_x509_* set of functions.
     * 
     * @return OpenSSLCertificate|null Peer site certificate
     */
    static function getPeerCert(): ?OpenSSLCertificate {
        if (count(self::$certChain) == 0)
            return null;
        return self::$certChain[0];
    }

    /**
     * Get the certificate chain from the visited site
     * 
     * When connecting to a https site, the certificate chain for the remote
     * site is retrieved, allowing extra validations. This method returns an
     * array with the complete certificate chain of the visited site.
     * The certificates can be proccesed with the openssl_x509_* set of functions.
     * 
     * @return array Certificate chain
     */
    static function getCertchain(): array {
        return self::$certChain;
    }

    /**
     * Set local certificate/key pair to authenticate connections
     * 
     * The parameters are the paths to the files containing the certificates encoded in PEM format.
     * If the certificate and the private key are stored in different files, you must provide both. 
     * 
     * @param string $certfile File with the certificate in PEM format
     * @param string $keyfile (optional) File with the private key in PEM format
     * @param string $passphrase (optional) Passphrase if keys are encrypted
     */
    static function setAuthCert(string $certfile, string $keyfile='', string $passphrase = '') {
        self::$localCert = $certfile;
        self::$localKey = $keyfile;
        self::$passphrase = $passphrase;
    }

    /**
     * Get the protocol version for the las HTTP request
     * 
     * @return string Protocol version
     */
    static function protocolVersion(): string {
        return self::$protversion;
    }

    /**
     * Get the status code for the last HTTP request
     * 
     * Normally, the status code is the return code from the HTTP connection (200,404,500, ..),
     * but this class adds two extra codes:
     * 
     * - -1: Invalid schema. Only http:// and https:// is supported
     * - -2: Invalid argument. Data passed to the method call is not valid
     * - -3: Network error. Network connection failed
     *
     * @return int Status code
     */
    static function respCode(): int {
        return self::$respcode;
    }

    /**
     * Get the status message for the last HTTP request
     *
     * @return string Status message
     */
    static function respStatus(): string {
        return self::$respstatus;
    }

    /**
     * Get the response headers for the last HTTP request
     *
     * @return array<string,string> Headers
     */
    static function respHeaders(): array {
        return self::$respheaders;
    }

    /**
     * Get the mime type of the response for the last HTTP request
     *
     * @return string Response data mime type
     */
    static function respMIME(): string {
        return self::$respmime;
    }

    /**
     * Get the data returned by the last HTTP request
     * 
     * @return string HTTP response
     */
    static function respBody(): string {
        return self::$respbody;
    }

    /**
     * Do a GET HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function get(string $url, array $headers = []): string {
        self::$method = 'GET';
        self::$url = $url;
        self::$body = '';
        self::mergeHeaders($headers);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a POST HTTP request
     *
     * @param string $url POST destination URL
     * @param array<string,mixed> $data Associative array with POST parameters
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function post(string $url, array $data, array $headers = []): string {
        self::$method = 'POST';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: application/x-www-form-urlencoded');
        self::mergeHeaders($headers);
        self::$body = http_build_query($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a POST HTTP request with the body data in JSON format
     *
     * @param string $url POST destination URL
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function postJSON(string $url, $data, array $headers = []): string {
        self::$method = 'POST';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: application/json');
        self::mergeHeaders($headers);
        self::$body = json_encode($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a POST HTTP request with the body in a custom format
     *
     * @param string $url POST destination URL
     * @param string $mime MIME type of the data
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function postRAW(string $url, string $mime, $data, array $headers = []): string {
        self::$method = 'POST';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: ' . $mime);
        self::mergeHeaders($headers);
        self::$body = json_encode($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a PUT HTTP request
     *
     * @param string $url POST destination URL
     * @param array<string,mixed> $data Associative array with POST parameters
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function put(string $url, array $data, array $headers = []): string {
        self::$method = 'PUT';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: application/x-www-form-urlencoded');
        self::mergeHeaders($headers);
        self::$body = http_build_query($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a PUT HTTP request with the body data in JSON format
     *
     * @param string $url POST destination URL
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function putJSON(string $url, $data, array $headers = []): string {
        self::$method = 'PUT';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: application/json');
        self::mergeHeaders($headers);
        self::$body = json_encode($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a PUT HTTP request with the body in a custom format
     *
     * @param string $url POST destination URL
     * @param string $mime MIME type of the data
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function putRAW(string $url, string $mime, $data, array $headers = []): string {
        self::$method = 'PUT';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: ' . $mime);
        self::mergeHeaders($headers);
        self::$body = json_encode($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a PATCH HTTP request
     *
     * @param string $url POST destination URL
     * @param array $data Associative array with POST parameters
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function patch(string $url, array $data, array $headers = []): string {
        self::$method = 'PATCH';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: application/x-www-form-urlencoded');
        self::mergeHeaders($headers);
        self::$body = http_build_query($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a PATCH HTTP request with the body data in JSON format
     *
     * @param string $url POST destination URL
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function patchJSON(string $url, $data, array $headers = []): string {
        self::$method = 'PATCH';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: application/json');
        self::mergeHeaders($headers);
        self::$body = json_encode($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a PATCH HTTP request with the body in a custom format
     *
     * @param string $url POST destination URL
     * @param string $mime MIME type of the data
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function patchRAW(string $url, string $mime, $data, array $headers = []): string {
        self::$method = 'PATCH';
        self::$url = $url;
        array_unshift($headers, 'Content-Type: ' . $mime);
        self::mergeHeaders($headers);
        self::$body = json_encode($data);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a HEAD HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function head(string $url, array $headers = []): string {
        self::$method = 'HEAD';
        self::$url = $url;
        self::$body = '';
        self::mergeHeaders($headers);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do a DELETE HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function delete(string $url, array $headers = []): string {
        self::$method = 'DELETE';
        self::$url = $url;
        self::$body = '';
        self::mergeHeaders($headers);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Do an OPTIONS HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    static function options(string $url, array $headers = []): string {
        self::$method = 'OPTIONS';
        self::$url = $url;
        self::$body = '';
        self::mergeHeaders($headers);
        self::execHTTP();
        return self::$respbody;
    }

    /**
     * Retrieve a PSR7 Response
     * 
     * This method return the result for the last request in a PSR7 message.
     * To use this method you must have installed one of the following packages:
     * httpsoft/http-message, nyholm/psr7, guzzle/psr7, laminas/laminas-diactoros
     * or slim/psr7
     * 
     * This method fires an Error if there isn't any PSR7 package installed
     * 
     * @return ResponseInterface Message in PSR7 format
     * @throws Error If there isn't any PSR7 package installed
     */
    static function PSRResponse(): ResponseInterface {
        if (class_exists('HttpSoft\Message\Response')) {
            $factory = new HStream;
            return new HResponse(self::$respcode, self::$respheaders, $factory->createStream(self::$respbody), self::$protversion, self::$respstatus);
        }
        if (class_exists('Nyholm\Psr7\Response')) {
            return new NResponse(self::$respcode, self::$respheaders, self::$respbody, self::$protversion, self::$respstatus);
        }
        if (class_exists('GuzzleHttp\Psr7\Response')) {
            return new GResponse(self::$respcode, self::$respheaders, self::$respbody, self::$protversion, self::$respstatus);
        }
        if (class_exists('Laminas\Diactoros\Response')) {
            $factory = new LStream;
            return new LResponse($factory->createStream(self::$respbody), self::$respcode, self::$respheaders);
        }
        if (class_exists('Slim\Psr7\Response')) {
            $h = new SHeaders(self::$respheaders);
            $o = fopen('php://memory', 'r+');
            fwrite($o, self::$respbody);
            fseek($o, 0);
            return new SResponse(self::$respcode, $h, new SSTream($o));
        }
        throw new Error(_('To use this method you must have installed one of the following packages') . ': ' . implode(', ',array_keys(self::RESPPACKAGES)));
    }

    /** @ignore */
    static public function verifyPSR7() {
        $out=new ConsoleOutput;
        foreach(self::RESPPACKAGES as $name=>$class) {
            if(class_exists($class)) {
                $out->writeln(sprintf('PSR7 will be provided by %s',$name));
                return;
            }
        }
        $out->writeln('<fg=red>There isn\'t any PSR7 package installed, you will not be able to use PSR7Response() method</>');
        $out->writeln('<fg=green>If you want to use it, you must install one of this packages:</>');
        foreach(self::RESPPACKAGES as $name=>$class) {
            $out->writeln('  <fg=blue>'.$name.'</>');
        }
        $out->writeln('<fg=green>-----</>');
    }
}
