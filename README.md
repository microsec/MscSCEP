MscSCEP client library for iOS 
==============================
Open-source implementation of [Simple Certificate Enrollment Protocol][1]. 
Version: 1.0.0

Requirements
------------
MscSCEP requires iOS 5.0 and above.

User third-party open-source library:
 - [OpenSSL][2]

Only **Foundation.framework** must be linked into the application for proper compilation.

Linker flags must be set:

 1. -ObjC
 2. -all_load

***ARC***
The entire codebase of MscSCEP use Automatic Reference Counting. If you are including the MscSCEP sources directly into a project that does not yet use Automatic Reference Counting, you will need to set the -fobjc-arc compiler flag on all of the MscSCEP source files.


Quick start guide
-----------------
Short examples for the implemented SCEP functions

####Download CA certificate (GetCACert operation)
To communicate with the SCEP server the client needs the certificate of SCEP server.
```
NSError* error; //MscSCEP informs you about the errors via NSError
NSString* documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0]; //path for the document directory
MscSCEP* scepClient = [[MscSCEP alloc] initWithURL:[NSURL URLWithString:@"http://teszt.e-szigno.hu/scep"]]; //initialize client library with the URL of scep server
NSArray* caCertificates = [scepClient downloadCACertificate:&error]; //download the certificate(s)
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}
MscCertificate* caCertificate = [caCertificates objectAtIndex:0]; //operation was successful, take the first certificate
NSString* caCertificateePath = [documentPath stringByAppendingPathComponent:@"caCertificate.cer"]; //path for the certificate
[caCertificate saveToPath:caCertificateePath error:&error]; //save certificate to the given path
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}
```
The number of certificates depends on the type of SCEP server. If the client directly communicates with the CA, the array should contain only one certificate. In case where a RA exist, the array can contain multiple certificate. For other SCEP operations you should use the first certificate in the array. 

####Certificate Enrollment (PKCSReq operation)
To request a certificate the client needs a RSA key and a self-signed certificate.
```
NSError* error; //MscSCEP informs you about the errors via NSError
NSString* documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0]; //path for the document directory
    
MscSCEP* scepClient = [[MscSCEP alloc] initWithURL:[NSURL URLWithString:@"http://teszt.e-szigno.hu/scep"]]; //initialize client library with the URL of scep server
    
MscRSAKey* rsaKey = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:&error]; //generate a new RSA key. It can be 2048 or 4096 bit long
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}

MscCertificateSubject* subject = [[MscCertificateSubject alloc] init]; //initialize a certificate subject with the given common name and country. You can specify the following attributes: common name (CN), locality name (L), state or province name (ST), organization name (O), organizational unit name (OU), country name (C), street address (STREET), domain component (DC) and user identifier (UID).
subject.commonName = @"MscSCEP tester";
subject.countryName = @"HU";

//initiliaze a certificate signing request with the following parameters
MscCertificateSigningRequest* csr = [[MscCertificateSigningRequest alloc] initWithSubject:subject //subject
                                    rsaKey:savedRSAkey //rsa key
                                    challengePassword:@"testclient" //challenge passowrd 
                                    fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&error]; //fingerprint algorithm. It can be MD5, SHA1, SHA256 and SHA512
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}

//initialize a self-signed certificate with the following parameters 
MscCertificate* certificate = [[MscCertificate alloc] initWithRequest:csr //certificate signing request 
                                rsaKey:rsaKey //rsa key 
                                error:&error];
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}

//request (enrol) a certificate with the following parameters
MscSCEPResponse* response = [scepClient enrolWithRSAKey:rsaKey //rsa key
                        certificateSigningRequest:csr //certificate signing request 
                        certificate:certificate //self-signed certificate
                        caCertificate:caCertificate //ca certificate which you can take with the downloadCACertificate function
                        createPKCS12:YES //with YES you can get the certificate and the PKCS12 object as well
                        pkcs12Password:@"123456" //password for PKCS12 
                        error:&error]; 
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}

if (response.pkiStatus == SCEPPKIStatus_PENDING) { //check response status
    [response pollWithError:&error]; //PENDING means, that the request pending for manual approval , try it again later
    if (nil != error) {
        NSLog(@"error occured: %d", error.code); //check NSError
    }
    if (response.pkiStatus == SCEPPKIStatus_SUCCESS) { //If SUCCESS, save certificate and pkcs12 to document directory
        MscCertificate* cert = [response.certificates objectAtIndex:0]; //enrolled certificate and the full certificate chain
        NSString* enrolledCertificatePath = [documentPath stringByAppendingPathComponent:@"enrolledCertificate.cer"]; //path to certificate
        [cert saveToPath:enrolledCertificatePath error:&error]; //save it to the given path
        if (nil != error) {
            NSLog(@"error occured: %d", error.code); //check NSError
        }
        
        MscPKCS12* pkcs12 = response.pkcs12; //pkcs12 object
        NSString* pkcs12Path = [documentPath stringByAppendingPathComponent:@"pkcs12.pfx"]; //path to pkcs12
        [pkcs12 saveToPath:pkcs12Path error:&error]; //save it to the given path
        if (nil != error) {
            NSLog(@"error occured: %d", error.code); //check NSError
        }
    }
}
```


####Certificate Access (GetCert operation)
According to the SCEP specification, the client does not have to store its own certificate, it can download it from the server if the serial number and the issuer of certificate is known. 
```
NSError* error; //MscSCEP informs you about the errors via NSError
NSString* documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0]; //path for the document directory
NSString* rsaPath = [documentPath stringByAppendingPathComponent:@"rsa.key"]; //path for your saved RSA key
MscRSAKey* rsaKey = [[MscRSAKey alloc] initWithContentsOfFile:rsaPath error:&error]; //initialize a rsa key instance with the path of key
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}

MscSCEP* scepClient = [[MscSCEP alloc] initWithURL:[NSURL URLWithString:@"http://teszt.e-szigno.hu/scep"]]; //initialize client library with the URL of scep server
[scepClient downloadCertificateWithRSAKey:rsaKey //your RSAKey
            issuer: issuer //issuer of your certificate (MscCertificateSubject instance)
            serial: serial //serial number of your certificate
            caCertificate:caCertificate //ca certificate which you can take with the downloadCACertificate function
            error:&error];
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}
```

####CRL Access (GetCRL operation)
To download a certificate revocation list the client needs a RSA key, a certificate (it can be self-signed) and needs to know the serial number and the issuer of the related certificate 
```
NSError* error; //MscSCEP informs you about the errors via NSError
NSString* documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0]; //path for the document directory
NSString* rsaPath = [documentPath stringByAppendingPathComponent:@"rsa.key"]; //path for your saved RSA key
MscRSAKey* rsaKey = [[MscRSAKey alloc] initWithContentsOfFile:rsaPath error:&error]; //initialize a rsa key instance with the path
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}
NSString* certificatePath = [documentPath stringByAppendingPathComponent:@"certificate.cer"]; //path for your certificate
MscCertificate* certificate = [[MscCertificate alloc] initWithContentsOfFile:certificatePath error:&error]; //initialize a certificate instance with the path
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}

MscSCEP* scepClient = [[MscSCEP alloc] initWithURL:[NSURL URLWithString:@"http://teszt.e-szigno.hu/scep"]]; //initialize client library with the URL of scep server

[scepClient downloadCRLWithRSAKey:rsaKey //your RSAKey
            certificate: certificate //your certificate
            issuer: issuer //issuer of the related certificate (MscCertificateSubject instance)
            serial: serial //serial number of the related certificate
            caCertificate:caCertificate //ca certificate which you can take with the downloadCACertificate function
            error:&error];
if (nil != error) {
    NSLog(@"error occured: %d", error.code); //check NSError
}
```

Public interfaces
----------
###MscSCEP
The main client functions of SCEP were implemented in **MscSCEP** interface.

####Instance methods
----------
```- (id)initWithURL:(NSURL*)_url```

Returns an initialized MscSCEP object.

#####Parameters:
_url: 
: URL of SCEP server

***Return value***: An initialized MscSCEP object.

***Declared in***: MscSCEP.h

----------

```- (NSArray*)downloadCACertificate:(NSError**)error```

Downloads the certificate of the SCEP server, which is required for the communication between the server and the client. The returned NSArray contains the certificate(s) of SCEP server.

#####Parameters:
error: 
: If an error occurs, upon return contains an NSError object that describes the problem. If you are not interested in possible errors, pass in NULL.

***Return value***: An array of MscCertificate object(s) 

***Declared in***: MscSCEP.h

----------

```- (MscSCEPResponse*)enrolWithRSAKey:(MscRSAKey*)rsaKey certificateSigningRequest:(MscCertificateSigningRequest*)certificateSigningRequest certificate:(MscCertificate*)certificate caCertificate:(MscCertificate*)caCertificate createPKCS12:(BOOL)createPKCS12 pkcs12Password:(NSString*)pkcs12Password error:(NSError**)error```

Wraps your certificate signing request in PKCS7 format, encrypts it for the SCEP server and signs it with your certificate and RSA key. Sends this SCEP message to the server and decrypts the response. If the enrollment was successful, the returned MscSCEPResponse instance contains your certificate.

#####Parameters:
rsaKey: 
: RSA key (MscRSAKey instance) which you can generate or load from filesystem.

certificateSigningRequest:
: Certificate signing request (MscCertificateSigningRequest instance) which you can generate or load from filesystem.

certificate:
: Certificate (MscCertificate instance) which you can generate or load from filesystem.

caCertificate:
: Certificate of CA (MscCertificate instance) which you can download with ```downloadCACertificate``` method or load from filesystem.

createPKCS12:
: BOOL value, if YES the method creates your PKCS12 object from your RSA key and the enrolled certificate, which will be protected by the given password.

pkcs12Password:
: This password will protect your PKCS12 object.

error:
: If an error occurs, upon return contains an NSError object that describes the problem. If you are not interested in possible errors, pass in NULL.

***Return value***: The response (MscSCEPResponse instance) of the server.

***Declared in***: MscSCEP.h

----------

```-(MscSCEPResponse*)downloadCRLWithRSAKey:(MscRSAKey*)rsaKey certificate:(MscCertificate*)certificate issuer:(MscCertificateSubject*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(NSError**)error```

Wraps the given issuer and serial number informations in PKCS7 format, encrypts it for the SCEP server and signs it with your certificate and RSA key. Sends this SCEP message to the server and decrypts the response. If the request was successful, the returned MscSCEPResponse instance contains your certificate revocation list. 

#####Parameters:
rsaKey: 
: RSA key (MscRSAKey instance) which you can generate or load from filesystem.

certificate:
: Certificate (MscCertificate instance) which you can generate or load from filesystem.

issuer:
: Issuer (MscCertificateSubject instance) of the related certificate, which you can get from the certificate with ```getIssuerWithError``` method.

serial:
: Serial number (NSString instance) of the related certificate, which you can get from the certificate with ```getSerialWithError``` method.

caCertificate:
: Certificate of CA (MscCertificate instance) which you can download with ```downloadCACertificate``` method or load from filesystem.

error:
: If an error occurs, upon return contains an NSError object that describes the problem. If you are not interested in possible errors, pass in NULL.

***Return value***: The response (MscSCEPResponse instance) of the server.

***Declared in***: MscSCEP.h

----------

```-(MscSCEPResponse*)downloadCertificateWithRSAKey:(MscRSAKey*)rsaKey issuer:(MscCertificateSubject*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(NSError**)error```

Wraps the given issuer and serial number informations in PKCS7 format, encrypts it for the SCEP server and signs it with a self-signed certificate and your RSA key. Sends this SCEP message to the server and decrypts the response. If the request was successful, the returned MscSCEPResponse instance contains your certificate. 

#####Parameters:
rsaKey: 
: RSA key (MscRSAKey instance) which you can generate or load from filesystem.

certificate:
: Certificate (MscCertificate instance) which you can generate or load from filesystem.

issuer:
: Issuer (MscCertificateSubject instance) of your certificate, which you can get from the certificate with ```getIssuerWithError``` method.

serial:
: Serial number (NSString instance) of your certificate, which you can get from the certificate with ```getSerialWithError``` method.

caCertificate:
: Certificate of CA (MscCertificate instance) which you can download with ```downloadCACertificate``` method or load from filesystem.

error:
: If an error occurs, upon return contains an NSError object that describes the problem. If you are not interested in possible errors, pass in NULL.

***Return value***: The response (MscSCEPResponse instance) of the server.

***Declared in***: MscSCEP.h

----------

###MscResponse
Most of MscSCEP methods return with MscResponse instance which contains status informations and returned objects (e.g. certificate, certificate revocation list, pkcs12 object, etc.)

####Instance methods
----------
```- (SCEPMessage)messageType```

Returns with the type of SCEP message, which can be CertRep, PKCSReq, GetCert, etc. 

***Return value***: Type of SCEP message.

***Declared in***: MscResponse.h

----------
```- (SCEPPKIStatus)pkiStatus```

Returns with the status of enrollment, which can be SUCCESS, FAILURE and PENDING. 

***Return value***: Status of enrollement. 

***Declared in***: MscResponse.h

----------
```- (SCEPFailInfo)failInfo```

Returns with the reason of failure if an error occured during the communication.

***Return value***: Reason of failure.

***Declared in***: MscResponse.h

----------
```- (NSArray*)certificates```

Returns with your enrolled certificates.

***Return value***: An array of certificates (MscCertificate object).

***Declared in***: MscResponse.h

----------
```- (NSArray*)certificateRevocationLists```

Returns with certificate revocation list.

***Return value***: An array of certificate revocation list (MscCertificateRevocationList object).

***Declared in***: MscResponse.h

----------
```- (MscPKCS12*)pkcs12```

Returns with enroller PKCS12 object.

***Return value***: Enrolled PKCS12 object which is protected by the given password (MscPKCS12 object).

***Declared in***: MscResponse.h

----------
```- (void)pollWithError:(NSError**)error```

In case ```pkiStatus``` is PENDING, you are able to poll the server and check the enrollment process result.

#####Parameters:
error:
: If an error occurs, upon return contains an NSError object that describes the problem. If you are not interested in possible errors, pass in NULL.

***Declared in***: MscResponse.h

----------
####Constants

#####Content-Types
MIME_GETCA and MIME_GETCA_RA: 
: Content-Type of ```downloadCACertificate``` operation

MIME_PKI:
: Content-Type of ```enrol```, ```downloadCRL``` and ```downloadCertificate``` operations

***Declared in***: MscResponse.h

----------
#####SCEP Message Type
These values represent the type of SCEP messages. According to the SCEP specification, the following message types were defined:

```
typedef NS_ENUM(NSUInteger, SCEPMessage) {
    SCEPMessage_None            = 0,    //undefined
    SCEPMessage_CertRep         = 3,    //Response to certificate or CRL request
    SCEPMessage_PKCSReq         = 19,   //PKCS#10 certificate request
    SCEPMessage_GetCertInitial  = 20,   //Certificate polling in manual enrollment
    SCEPMessage_GetCert         = 21,   //Retrieve a certificate
    SCEPMessage_GetCRL          = 22    //Retrieve a CRL
};
```
----------
#####SCEP pki status
These values represent the transaction status information. According to the SCEP specification, the following pki statuses were defined:

```
typedef NS_ENUM(NSUInteger, SCEPPKIStatus) {
    SCEPPKIStatus_SUCCESS   = 0,    //request granted
    SCEPPKIStatus_FAILURE   = 2,    //request rejected
    SCEPPKIStatus_PENDING   = 3     //request pending for manual approval
};
```

----------
#####SCEP failInfo
These values represent the reason of failure. According to the SCEP specification, the following failInfos were defined:

```
typedef NS_ENUM(NSUInteger, SCEPFailInfo) {
    SCEPFailInfo_BadAlg             = 0,    //Unrecognized or unsupported algorithm identifier
    SCEPFailInfo_BadMessageCheck    = 1,    //integrity check failed
    SCEPFailInfo_BadRequest         = 2,    //transaction not permitted or supported
    SCEPFailInfo_BadTime            = 3,    //The signingTime attribute from the PKCS#7 authenticatedAttributes was not                                                //sufficiently close to the system time
    SCEPFailInfo_BadCertId          = 4,    //No certificate could be identified matching the provided criteria
    SCEPFailInfo_NoError            = 1000  //undefined
};
```


Testing
-------
For testing purposes you can use our TEST SCEP environment. 

SCEP Server URL: http://teszt.e-szigno.hu/scep

Challenge passwords by key usage: 
- authentication: githubclient-aut
- encryption:     githubclient-ke
- signature:      githubclient-ds       

License
-------
MscSCEP is available under GPLv2 license. In case where the contraints of the GPLv2 license is prevent you from using MscSCEP library or you would like to avoid the restrictions of the GPLv2 license, you can purchase a commercial license. For more information, please contact us: sales@microsec.hu


  [1]: http://tools.ietf.org/html/draft-nourse-scep
  [2]: http://www.openssl.org/
