***

# SHTTP

Wrapper class around file_get_contents function. This class is not intended
to compete with full featured network frameworks, as Guzzle or Swoole, but
to provide a simple and convenient solution to use web services or access
web resources

This class provides a set of static methods that can be called without creating any object.

* Full name: `\SHTTP`

**See Also:**

* https://github.com/sirmonti/shttp/ - SHTTP github project



## Properties


### verifCERT

Enable/Disable certificate verification on https connections.

```php
public static bool $verifCERT
```

When connecting to a https site, the program verify if the
certificate is valid and fires an error if not. Disabling certificate validation
you can prevent this error and connect to sites with faulty certificate.
You can edit this value to change default value.

* This property is **static**.


***

### followRedirs

If request returns a redirection, it must be followed.

```php
public static bool $followRedirs
```



* This property is **static**.


***

### reqFullURI

On the request command, send the full URI instead the path.

```php
public static bool $reqFullURI
```

For example, instead send "GET /test.html HTTP/1.1" command to the server,
script will send "GET http://www.example.com/test.html HTTP/1.1".
Include full URI breaks standard, but is neccesary if connect to a proxy.

* This property is **static**.


***

### maxfollows

How many redirections must be followed before a "Many redirections"
error must be fired

```php
public static int $maxfollows
```



* This property is **static**.


***

### timeout

Connection timeout. Connection closes if exceds timeout without
response. Default value is ten seconds.

```php
public static float $timeout
```



* This property is **static**.


***

### exceptlevel

Exception level. You can edit this value to change default value

```php
private static int $exceptlevel
```

Expected values:

- 0: No exceptions
- 1: Exception only on network errors or invalid arguments
- 2: Exception on HTTP errors (4XX and 5XX errors) too

* This property is **static**.


***

## Methods


### setExceptionLevel

Set exception level

```php
public static setExceptionLevel(int $level): void
```

This method configures the use of exceptions on an error. There are three exception levels

- 0: No exceptions fired. Operations results are returned in httpcode and httpstatus
- 1: Exceptions only on network errors or bad formed URLs. HTTP errors don't fire exceptions
- 2: All errors fire an exception.

* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$level` | **int** | Exception level |





***

### getExceptionLevel

Get the configured exception level

```php
public static getExceptionLevel(): int
```



* This method is **static**.





**Return Value:**

Configured exception level




***

### setProxy

Set the proxy server

```php
public static setProxy(string $host = &#039;&#039;, int $port = 8080): bool
```

You provide the host name or IP address and port

* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$host` | **string** | Proxy host |
| `$port` | **int** | Proxy port |


**Return Value:**

Proxy has been set OK




***

### getProxy

Get the proxy parameters

```php
public static getProxy(string& $host, int& $port): mixed
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$host` | **string** | Filled with proxy host name or IP |
| `$port` | **int** | Filled with proxy port |





***

### setExtraHeaders

Define a set of extra headers to be attached to following requests

```php
public static setExtraHeaders(array&lt;int,string&gt; $headers = []): mixed
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$headers` | **array<int,string>** | Extra headers to set |





***

### getExtraHeaders

Get the extra headers, if any

```php
public static getExtraHeaders(): array&lt;int,string&gt;
```



* This method is **static**.





**Return Value:**

Configured extra headers




***

### getSendHeaders

Get the headers that has been sent on last request

```php
public static getSendHeaders(): array
```

If you call this method before any request, it will
return default headers.

* This method is **static**.





**Return Value:**

Header sent on last request




***

### getSendBody

Get the body that has been sent on last request

```php
public static getSendBody(): string
```

If you call this method before any request, it will
return an empty string.

* This method is **static**.





**Return Value:**

Body sent on last request




***

### getPeerCert

Get the peer certificate from the visited site

```php
public static getPeerCert(): \OpenSSLCertificate|null
```

When connecting to a https site, the certificate chain for the remote
site is retrieved, allowing extra validations. This method returns the
certificate of the visited site. The certificate can be proccesed with
the openssl_x509_* set of functions.

* This method is **static**.





**Return Value:**

Peer site certificate




***

### getCertchain

Get the certificate chain from the visited site

```php
public static getCertchain(): array
```

When connecting to a https site, the certificate chain for the remote
site is retrieved, allowing extra validations. This method returns an
array with the complete certificate chain of the visited site.
The certificates can be proccesed with the openssl_x509_* set of functions.

* This method is **static**.





**Return Value:**

Certificate chain




***

### setAuthCert

Set local certificate/key pair to authenticate connections

```php
public static setAuthCert(string $certfile, string $keyfile = &#039;&#039;, string $passphrase = &#039;&#039;): mixed
```

The parameters are the paths to the files containing the certificates encoded in PEM format.
If the certificate and the private key are stored in different files, you must provide both.

* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$certfile` | **string** | File with the certificate in PEM format |
| `$keyfile` | **string** | (optional) File with the private key in PEM format |
| `$passphrase` | **string** | (optional) Passphrase if keys are encrypted |





***

### protocolVersion

Get the protocol version for the las HTTP request

```php
public static protocolVersion(): string
```



* This method is **static**.





**Return Value:**

Protocol version




***

### respCode

Get the status code for the last HTTP request

```php
public static respCode(): int
```

Normally, the status code is the return code from the HTTP connection (200,404,500, ..),
but this class adds two extra codes:

- -1: Invalid schema. Only http:// and https:// is supported
- -2: Invalid argument. Data passed to the method call is not valid
- -3: Network error. Network connection failed

* This method is **static**.





**Return Value:**

Status code




***

### respStatus

Get the status message for the last HTTP request

```php
public static respStatus(): string
```



* This method is **static**.





**Return Value:**

Status message




***

### respHeaders

Get the response headers for the last HTTP request

```php
public static respHeaders(): array&lt;string,string&gt;
```



* This method is **static**.





**Return Value:**

Headers




***

### respMIME

Get the mime type of the response for the last HTTP request

```php
public static respMIME(): string
```



* This method is **static**.





**Return Value:**

Response data mime type




***

### respBody

Get the data returned by the last HTTP request

```php
public static respBody(): string
```



* This method is **static**.





**Return Value:**

HTTP response




***

### get

Do a GET HTTP request

```php
public static get(string $url, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### post

Do a POST HTTP request

```php
public static post(string $url, array&lt;string,mixed&gt; $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **array<string,mixed>** | Associative array with POST parameters |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### postJSON

Do a POST HTTP request with the body data in JSON format

```php
public static postJSON(string $url, mixed $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### postRAW

Do a POST HTTP request with the body in a custom format

```php
public static postRAW(string $url, string $mime, mixed $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$mime` | **string** | MIME type of the data |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### put

Do a PUT HTTP request

```php
public static put(string $url, array&lt;string,mixed&gt; $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **array<string,mixed>** | Associative array with POST parameters |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### putJSON

Do a PUT HTTP request with the body data in JSON format

```php
public static putJSON(string $url, mixed $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### putRAW

Do a PUT HTTP request with the body in a custom format

```php
public static putRAW(string $url, string $mime, mixed $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$mime` | **string** | MIME type of the data |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### patch

Do a PATCH HTTP request

```php
public static patch(string $url, array $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **array** | Associative array with POST parameters |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### patchJSON

Do a PATCH HTTP request with the body data in JSON format

```php
public static patchJSON(string $url, mixed $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### patchRAW

Do a PATCH HTTP request with the body in a custom format

```php
public static patchRAW(string $url, string $mime, mixed $data, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$mime` | **string** | MIME type of the data |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### head

Do a HEAD HTTP request

```php
public static head(string $url, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### delete

Do a DELETE HTTP request

```php
public static delete(string $url, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### options

Do an OPTIONS HTTP request

```php
public static options(string $url, array&lt;string,string&gt; $headers = []): string
```



* This method is **static**.




**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### PSRResponse

Retrieve a PSR7 Response

```php
public static PSRResponse(): \ResponseInterface
```

This method return the result for the last request in a PSR7 message.
To use this method you must have installed one of the following packages:
httpsoft/http-message, nyholm/psr7, guzzle/psr7, laminas/laminas-diactoros
or slim/psr7

This method fires an Error if there isn't any PSR7 package installed

* This method is **static**.





**Return Value:**

Message in PSR7 format



**Throws:**
<p>If there isn't any PSR7 package installed</p>

- [`Error`](./Error.md)



***


***
> Automatically generated on 2024-04-27
