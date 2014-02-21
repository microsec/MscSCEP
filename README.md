MscSCEP
=======
SCEP client library for iOS


Documentation
=============
The following SCEP client functions were implemented:

Download CA Certificate
-----------------------
You are able to download the certificate of the SCEP server in the following way:
```Objective-C
1. MscSCEP* scepClient = [[MscSCEP alloc] initWithURL:[NSURL URLWithString:@"http://teszt.e-szigno.hu/scep"]];
2. NSArray* caCertificates = [scepClient downloadCACertificate:&error];
```
######Details:
1. initialize the SCEP client with the url of SCEP server. The default init method is disabled, you can use the initWithURL method for initialization. For testing purposes you can use our SCEP server. 
2. downloadCACertificate method returns with the server certificate(s). If something went wrong, it will return with nil and the error informs you about the details. The number of returned certificates depends on the SCEP server. If it is a CA, the array sould contain only one certificate, if it is a RA, the array can contain multiple certificates. 

Enrol
-----
You are able to request certificate from SCEP server in the following way:

```Objective-C
1.  NSString* documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
2.  MscSCEP* scepClient = [[MscSCEP alloc] initWithURL:[NSURL URLWithString:@"http://teszt.e-szigno.hu/scep"]];
3.  MscRSAKey* rsaKey = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:&error];
4.  MscCertificateSubject* subject = [[MscCertificateSubject alloc] init];
5.  subject.commonName = @"MscSCEP tester";
6.  subject.countryName = @"HU";
7.  MscCertificateSigningRequest* csr = [[MscCertificateSigningRequest alloc] initWithSubject:subject rsaKey:rsaKey challengePassword:@"githubclient-ds" fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&error];
8.  MscCertificate* certificate = [[MscCertificate alloc] initWithRequest:csr rsaKey:rsaKey error:&error];
9.  MscSCEPResponse* response = [scepClient enrolWithRSAKey:rsaKey certificateSigningRequest:csr certificate:certificate caCertificate:caCertificate createPKCS12:YES pkcs12Password:@"123456" error:&error];
10. if (response.pkiStatus == SCEPPKIStatus_PENDING) {
11.   [response pollWithError:&error];
12.   if (response.pkiStatus == SCEPPKIStatus_SUCCESS) {
13.     MscCertificate* cert = [response.certificates objectAtIndex:0];
14.     NSString* enrolledCertificatePath = [documentPath stringByAppendingPathComponent:@"enrolledCertificate.cer"];
15.     [cert saveToPath:enrolledCertificatePath error:&error];
16.     NSString* pkcs12Path = [documentPath stringByAppendingPathComponent:@"pkcs12.pfx"];
17.     MscPKCS12* pkcs12 = response.pkcs12;
18.     [pkcs12 saveToPath:pkcs12Path error:&error];
19.   }
20. }
```
######Details:
1. get the path for document directory. It will be neccesary later.
2. initialize the SCEP client with the url of SCEP server. The default init method is disabled, you can use the initWithURL method for initialization. For testing purposes you can use our SCEP server. 
3. generate a RSA keypair. The default init method is disabled, you can use the initWithKeySize for initialization. Keysize can be: KeySize_2048 or KeySize_4096.
4. initialize a MscCertificateSubject object. It will be necessary to generate the certificate signing request. You can specify the ordinary certificate subject properties, e.g.: commonName, localityName, stateOrProvinceName, organizationName, etc. 
5. and 6. set commonName and countryName
7. initalize a MscCertificateSigningRequest object. The default init method is disabled, you can use the initWithSubject for initialization. Be careful for the challengePassword parameters, this password use the SCEP server for authorize your request during the enrol process. For testing purposes you are able to use the following challenge passwords: githubclient-aut, githubclient-ke, githubclient-ds. More details in Testing section.
8. initialize a MscCertificate object. The default init method is disabled, you can use the initWithRequest for initialization. 
9. start the enrol process. The method will return with a MscSCEPResponse instance. If something went wrong, it will return with nil and the error informs you about the details. If you set the createPKCS12 and the pkcs12Password parameters, the client will generate a MscPKCS12 object which will be protected with the pkcs12Password. 
10. check the response status. It can be: SCEPPKIStatus_SUCCESS, SCEPPKIStatus_FAILURE or SCEPPKIStatus_PENDING. If something went wrong and the response status is SCEPPKIStatus_FAILURE, you can check the failInfo property for the reason
11. if the response status is SCEPPKIStatus_PENDING you are able to poll the SCEP server 
12. if the response status is SCEPPKIStatus_SUCCESS, you can handle the response properties
13. in enrol process certificates array should contain only one MscCertificate instance
14. specify the path for certificate
15. save the MscCertificate instance to the path
16. specify the path for pkcs12 
17. the pkcs12 property contains the MscPKCS12 instance if the createPKCS12 parameter was YES
18. save the MscPKCS12 instance to the path

Download CRL
------------
Documentation soon...

Download Certificate
--------------------
Documentation soon...

Testing
=======
Documentation soon...

License
=======
MscSCEP is available under GPLv2 license. In case where the contraints of the GPLv2 license is prevent you from using MscSCEP library or you would like to avoid the restrictions of the GPLv2 license, you can purchase a commercial license. For more information, please contact us: sales@microsec.hu
