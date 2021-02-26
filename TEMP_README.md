TEMPORARY FILE -- CHECK FOR EVERY ADDED TEST IF THEY ARE CORRECT.

## THINGS TO CHECK:
* a. Is the root signature correct (i.e. is `validSignature = true;` run on saml.ts:859)  
* b. Is the expected number of validation checks correct  
* c. Is the expected error thrown (i.e. "SAML assertion expired" if we made it past certificate validation, see test-signatures.spec.ts:38)  


## TESTS TO CHECK:

1.  signed response with unsigned unencrypted assertion
    - expected result is invalid signature
2.  signed response with unsigned encrypted assertion
        because program logic ("if" statement which determines when assetion signature should be checked) is and has been duplicated to code blocks which handle encrypted and unencrypted assertions
    - expected result is invalid signature
3.  unsigned response with signed unencrypted assertion and cert option not provided at all
        because passport-saml can be configured without cert by not defining that configuration attribute at all (see issues 180 and 523) in which case passport-saml shall allow anyone to manipulate login response. This would be against WantAssertionsSigned = true and passport-saml should assume that desired behaviour is validly signed assertion (i.e. if passport-saml implementation is not modified to fail during stack setup phase due conflicting configuration parameters assertion validation should fail at least during validation of signature by XML signature library due undefined cert)
    - expected result is invalid signature
4.  unsigned response with with signed encrypted assertion and certoption not provided at all (see 3.)
        reason behind this is duplicated program logic (aforementioned "if" statement)
    - expected result invalid signature
5.  signed response with signed unencrypted assertion so that assertions content (e.g. nameid) is modified after calculation of assertion's signature but prior to signing response (i.e. response's signature is valid but assertion's signature would not be)
    - expected result invalid signature
6.  signed response with signed encrypted assertion so that assertion's content doesn't match with assertion's signature
        i.e. same as 5. but for encrypted assertion (e.g. by modifying assertion's nameid after assertion's signature is calculated but prior to encrypting assertion and signing response)
    - expected result invalid signature

## RESULTS:

### 1. signed response with unsigned unencrypted assertion

Test name: `R1A - root signed - wantAssertionsSigned=true => error`  
Response xml: `/valid/response.root-signed.assertion-unsigned.xml`

* a:
* b:
* c:

### 2. signed response with unsigned encrypted assertion

Test name: `R1A - root signed - asrt unsigned encrypted -wantAssertionsSigned=true => error`  
Response xml: `/valid/response.root-signed.assertion-unsigned-encrypted.xml` 

* a:
* b:
* c:

### 3. unsigned response with signed unencrypted assertion and cert option not provided at all

Test name:  
Response xml:

* a:
* b:
* c:

### 4. unsigned response with with signed encrypted assertion and certoption not provided at all

Test name:  
Response xml:

* a:
* b:
* c:

### 5. signed response with signed unencrypted assertion so that assertions content (e.g. nameid) is modified after calculation of assertion's signature but prior to signing response

Test name:  
Response xml:

* a:
* b:
* c:

### 6. signed response with signed encrypted assertion so that assertion's content doesn't match with assertion's signature

Test name:  
Response xml:

* a:
* b:
* c:
