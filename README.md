# Transformer
BurpSuite extension to convert HTTP requests.

## Installation
Add extension:
```
Extender -> Add -> Extension type (Python) -> Select file ... (transformer.py)
```

## Use case I
You are testing entry point that accepts base64-encoded values (X-User-Id) and you want to run Scanner on this:
```
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
X-User-Id: ODkyNDM1

```
You can define the following entry point in the Intruder and run Scanner:
```
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
X-User-Id: {tr:b64()}§892435§{tr}

```
Any payloads generated by the Scanner e.g.
```
X-User-Id: {tr:b64()}'and''='{tr}
X-User-Id: {tr:b64()}../../../../../../../../../etc/passwd{tr}
end so on...
```
Will be replaced by the Transformer to the following values:
```
X-User-Id: J2FuZCcnPSc=
X-User-Id: Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==
end so on...
```

There are more encoding transformations:
1. b64()
1. jwt()
1. hex()
1. json()
1. url()

Transformations can be chained using & operator:
```
X-User-Id: {tr:b64()&url()&hex()}'and''='{tr}
```
The above value will be transformed to the following one:
```
X-User-Id: 4a3246755a43636e505363253344
```
What can be sequentially decoded to the following values:
```
4a3246755a43636e505363253344
J2FuZCcnPSc%3D
J2FuZCcnPSc=
'and''='
```

There may be multiple (not nested) transformations in the request:
```
POST / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
X-User-Id: {tr:b64()}§892435§{tr}
Content-Length: 22

name={tr:hex()}§Foo§{tr}
```

## Use case II
Testing JWT (None algorithm attack) using Repeater:
```
GET /index.php HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: auth={tr:jwt()}{"alg":"None","typ":"JWS"}{tr}.{tr:jwt()}{"login":"admin","iat":"1605373370"}{tr}.
Upgrade-Insecure-Requests: 1
```

## Use case III
Other use case is testing registration form with unique email address requirement.
You can define the following entry points in the Intruder and run Scanner:
```
POST /register HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 67

name=§foo§&lastname=§bar§&email=§foo+{tr:random(1,1000)}{tr}@example.com§
```
{tr:random(1,1000)}{tr} expression will be replaced with the random values (from 1 to 1000), e.g.:
```
POST /register HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 47

name=foo&lastname=bar&email=foo+115@example.com
```

## Use case IV
Other useful transformation is long(len).
Let's say you want to use Repeater to check how the login mechanism copes with a very long password:
```
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pl,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 39

user=foo&password={tr:long(100000)}{tr}
```
{tr:long(100000)}{tr} expression will be replaced with 100000 characters long string.

There are more data generating transformations:
1. random(min, max)
1. long(len)
1. uuid()

Data generating and encoding transformations can be chained using & operator, e.g.:
```
name=foo&lastname={tr:long(50)&b64()&url()}{tr}
```
The above value will be transformed to the following one:
```
name=foo&lastname=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE%3D
```

## Own transformations
It is possible to define own transformation.
Just add a new one to the transformations list and reload the extension.
By default the following transformations are available:
```python
transformations = {
    # encoders
    'b64': lambda params, data: base64.b64encode(data),
    'jwt': lambda params, data: base64.urlsafe_b64encode(data).replace(b'=', b''),
    'hex': lambda params, data: binascii.hexlify(data),
    'json': lambda params, data: json.dumps(data)[1:-1],
    'url': lambda params, data: urllib.quote(data),

    # data generators
    'uuid': lambda params, data: str(uuid.uuid4()),
    'long': lambda params, data: 'a' * int(params[0]),
    'random': lambda params, data: str(random.randint(int(params[0]), int(params[1]))),
}
```
A new transformation could look like this:
```python
transformations = {
[...]
    'repeat': lambda params, data: data * int(params[0]),
}
```
Using repeat(times) transformation:
```
name={tr:random(1,100)&repeat(3)}{tr}
```

## Limitations
1. Transformations can not be nested.
{tr:b64()}{tr:long(10)}{tr}{tr} does not work as expected.
Use chaining instead.
1. Transformations parser is a simple (naive) regexp-based implementation and could not work when special characters will be used as a transformation parameter.
Let's say you define transformation that accepts string parameter, using it as follow {tr:foo(abc&de)}{tr} will not work.
1. Transformer is a simple tool that was created to deal with the specific cases I noticed during my work, and may not support all possible inputs, e.g. b64() transformer will fail for non-ascii data.
In such case, just write own transformation that will handle your specific case.

## Warnings
Please be aware that Transformer extension works globally (for all BurpSuite tools).
This may be dangerous if you testing untrusted application, especially if you defined own transformation doing dangerous operations, such like file system access.

## Tips
Excellent [Loger++](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81) extension it is very useful in creating own transformation (allows to see result of the transformation).

## Changes
Please see the [CHANGELOG](CHANGELOG)
