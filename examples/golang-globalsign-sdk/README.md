# Testing compatibility with other EST Clients/SDKs

## Results

* Server should supported requests to `simpleenroll` with the following headers. 
    * `Content-Type: application/pkcs10`
    * `Content-Transfer-Encoding: base64`

    Currently Cumulocity requires the `Content-Type` header is set to `text/plain` - which does not conform to the EST spec)

    See the [EST specification - RFC7030](https://datatracker.ietf.org/doc/html/rfc7030#section-4.2.1)

    > The HTTP content-type of "application/pkcs10" is used here. The format of the message is as specified in [RFC5967] with a Content-Transfer-Encoding of "base64" [RFC2045].

* Response (see https://datatracker.ietf.org/doc/html/rfc7030#appendix-A.3 for an example of the full request/response with headers and response formats etc.)
    * Response is missing the smime-type addition to the `Content-Type` header, e.g. `Content-Type: application/pkcs7-mime; smime-type=certs-only`

        The specification says the following (https://datatracker.ietf.org/doc/html/rfc7030#section-4.2.3):

        > The HTTP content-type of "application/pkcs7-mime" with an smime-type parameter "certs-only" is used, as specified in [RFC5273]
    
    * Response is missing the `Content-Transfer-Encoding: base64` header

    * Response body is not in the correct format. The expected format is `application/pkcs7-mime; smime-type=certs-only`. But currently the response seems to be in the PKCS#10 format (base64 encoded)


### Testing Notes

* You can use the https://github.com/globalsign/est server to check the compatibility between different clients and compare with the Cumulocity implementation

* You can check if the response is in the correct format by using online service https://certlogik.com/decoder/ (or openssl), but the decoded response should show it is in the "PKCS#7" format


## Languages

### golang

#### Library - https://github.com/globalsign/est


* Content-Type header is not configurable and the default value is `application/pkcs10`. If the default is used, then the request is rejected by the server with a HTTP 415 Unsupported Media Type response.

* Response is checked if it contains the `Content-Transfer-Encoding` header which it expects it to container `base64` to align with the `Content-Type` of `application/pkcs7-mime`

* The pkcs7 parsing fails. The mozilla pkcs7 library is used: "go.mozilla.org/pkcs7"

    ```log
    panic: failed to decode PKCS7: asn1: structure error: tags don't match (6 vs {class:0 tag:16 length:408 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} ObjectIdentifier @4
    ```


#### Library - https://github.com/thales-e-security/estclient

* Invalid content type, it does not accept `text/plain` as a Content-Type

* The pkcs7 parsing fails. The mozilla pkcs7 library is used: "github.com/fullsailor/pkcs7"

### python

#### Library - github.com/laurentluce/est-client-python

* Client uses `Content-Type: application/pkcs10`, so without hacking the library, the request is rejected by the server with a 415 HTTP status code

* unable to parse PKCS7 data (using `pkcs7.load_pem_pkcs7_certificates` from the Python `cryptography` lib based in Rust)

```
Unable to parse PKCS7 data
  File "/Users/reubenmiller/dev/projects/thin-edge.io/code/c8y-pki-check/examples/python/main.py", line 11, in ConvertPkcs7ToPem
    newCerts = pkcs7.load_pem_pkcs7_certificates(in_bytes)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/reubenmiller/dev/projects/thin-edge.io/code/c8y-pki-check/examples/python/main.py", line 54, in <module>
    client_cert_pem = ConvertPkcs7ToPem(client_cert)
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/opt/homebrew/Cellar/python@3.12/3.12.6/Frameworks/Python.framework/Versions/3.12/lib/python3.12/runpy.py", line 88, in _run_code
    exec(code, run_globals)
  File "/opt/homebrew/Cellar/python@3.12/3.12.6/Frameworks/Python.framework/Versions/3.12/lib/python3.12/runpy.py", line 198, in _run_module_as_main (Current frame)
    return _run_code(code, main_globals, None,
ValueError: Unable to parse PKCS7 data
```

### C

#### Library - github.com/lgtti/rfc7030-est-client

* https://github.com/lgtti/rfc7030-est-client/blob/0ad5e39aed9301a31a8446843e97e0404aee63be/src/lib/enroll.c#L183

* Client library uses the following HTTP headers to request a certificate
    * `Content-Type: application/pkcs10`
    * `Content-Transfer-Encoding: base64`
    * `Accept: */*`
