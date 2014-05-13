MscSCEP client library for iOS
==============================
Native Objective-C implementation of SCEP. 
Latest version: 1.0.0

Quick start guide
-----------------
Short examples for the implemented SCEP functions

#### Download CA certificate
To communicate with the SCEP server you have to have the certificate of SCEP server.
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
The number of certificates depends on the type of SCEP server. If it is a CA, the array sould contain only one certificate, if it is a RA, the array can contain multiple certificates. You should always use the first certificate. 

#### Request (enrol) certificate
To request a certificate you have to have a RSA key, and a self-signed certificate.
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
    [response pollWithError:&error]; //If PENDING, try it again
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


#### Download certificate
According to the SCEP specification, you do not have to store your certificate, it is enough to know the serial number and the issuer of your certificate. 
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

#### Download certificate revocation list
To download a certificate revocation list you have to have a RSA key, a certificate (it can be self-signed) and need to know the serial number and the issuer of the related certificate 
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
