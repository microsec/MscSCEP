//
//  MscSCEP.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.13..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEP.h"
#import "MscSCEPLocalException.h"
#import "MscSCEPMessageUtils.h"
#import "NSString+MscRandomExtension.h"

#import "MscHTTPSURLConnection/MscHTTPSURLConnection.h"

#import "MscX509Common/MscCertificate_OpenSSL_X509.h"
#import "MscX509Common/MscCertificateUtils.h"

#import <openssl/pkcs12.h>

@implementation MscSCEP {
    
@private
    NSURL* url;
}

+ (void)initialize {
    
    OpenSSL_add_all_algorithms();
}

-(id)initWithURL:(NSURL*)_url {
    
    if (self = [super init]) {
        url = _url;
        return self;
    }
    return nil;
}

-(NSArray*)decodeCACertificatesWithData:(NSData*)payLoad error:(MscSCEPError**)error {
    
    PKCS7* pkcs7 = NULL;
    
    @try {
        
        //it should be a DER encoded PKCS7 object
        const unsigned char* payLoadData = [payLoad bytes];
        
        pkcs7 = d2i_PKCS7(NULL, &payLoadData, [payLoad length]);
        if (!pkcs7) {
            NSLog(@"Failed to read server certificate, function: d2i_PKCS7");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        if (OBJ_obj2nid(pkcs7->type) != NID_pkcs7_signed) {
            NSLog(@"Failed to download server certificate, pkcs7 object type is not pkcs7_signed");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        STACK_OF(X509) *caCertificates = pkcs7->d.sign->cert;
        
        if (!caCertificates) {
            NSLog(@"Failed to download server certificate, certificates are missing from pkcs7 object");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        NSMutableArray* certificates = [[NSMutableArray alloc] initWithCapacity:sk_X509_num(caCertificates)];
        for (int i = 0; i < sk_X509_num(caCertificates); i++) {
            X509* cert = X509_dup(sk_X509_value(caCertificates, i));
            [certificates addObject:[[MscCertificate alloc] initWithX509: cert]];
        }
        
        return certificates;
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
    }
    @finally {
        if (pkcs7) PKCS7_free(pkcs7);
    }
}

-(void)downloadCACertificateWithValidatorDelegate:(id<MscHTTPSValidatorDelegate>)validatorDelegate completionHandler:(MscSCEPDownloadCACertificateCompletionHandler)completionHandler {
    
    NSURL* getCAURL = [NSURL URLWithString: [NSString stringWithFormat:@"%@?operation=GetCACert&message=%@", [url absoluteString], @"CAIdentifier"]];
    
    NSURLRequest* getCARequest = [NSURLRequest requestWithURL:getCAURL cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:60.0];
    
    MscHTTPSURLConnection* connection = [[MscHTTPSURLConnection alloc] init];
    [connection sendAsynchronousRequest:getCARequest identity:nil identityPassword:nil validatorDelegate:validatorDelegate completionHandler:^(NSHTTPURLResponse* response, NSData* payLoad, MscHTTPSURLConnectionError* connectionError){
        
        if (connectionError) {
            completionHandler(nil, [MscSCEPError errorWithCode:connectionError.code]);
            return;
        }
        
        if ([[response MIMEType] isEqual: MIME_GETCA]) {
            
            //it should be a DER encoded X.509 object
            MscX509CommonError* certError;
            MscCertificate* caCertificate = [[MscCertificate alloc] initWithData:payLoad error:&certError];
            if (certError) {
                completionHandler(nil, [MscSCEPError errorWithCode:certError.code]);
                return;
            }
            
            completionHandler([NSArray arrayWithObject:caCertificate], nil);
        }
        else if ([[response MIMEType] isEqual: MIME_GETCA_RA]) {
            
            MscSCEPError* decodeError;
            NSArray* caCertificates = [self decodeCACertificatesWithData:payLoad error:&decodeError];
            if (decodeError) {
                completionHandler(nil, [MscSCEPError errorWithCode:decodeError.code]);
                return;
            }
            
            completionHandler(caCertificates, nil);
        }
        else {
            
            NSLog(@"Failed to download server certificate, mime type of server response: %@", [response MIMEType]);
            completionHandler(nil, [MscSCEPError errorWithCode:FailedToDownloadCACertificate]);
            return;
        }
    }];
}

-(MscSCEPResponse*)enrollWithRSAKey:(MscRSAKey*)rsaKey certificateSigningRequest:(MscCertificateSigningRequest*)certificateSigningRequest certificate:(MscCertificate*)certificate caCertificate:(MscCertificate*)caCertificate createPKCS12:(BOOL)createPKCS12 pkcs12Password:(NSString*)pkcs12Password error:(MscSCEPError**)error {
    
    @try {
        
        NSAssert(rsaKey != nil, @"rsaKey parameter is missing");
        NSAssert(certificateSigningRequest != nil, @"certificateSigningRequest parameter is missing");
        NSAssert(certificate != nil, @"certificate parameter is missing");
        NSAssert(caCertificate != nil, @"caCertificate parameter is missing");
        
        MscSCEPTransaction* transaction = [[MscSCEPTransaction alloc] init];
        transaction.scepServerURL = url;
        transaction.senderNonce = [NSString randomAlphanumericStringWithLength:16];
        
        MscX509CommonError* x509Error;
        transaction.transactionID = [MscCertificateUtils getCertificatePublicKeyFingerPrint:certificate error:&x509Error];
        if (x509Error) {
            @throw [MscSCEPLocalException exceptionWithCode:x509Error.code];
        }
        
        transaction.createPKCS12 = createPKCS12;
        transaction.pkcs12Password = pkcs12Password;
        
        transaction.signerKey = rsaKey;
        transaction.signerCertificate = certificate;
        transaction.caCertificate = caCertificate;
        transaction.certificateSigningRequest = certificateSigningRequest;
        
        MscSCEPError* createAndSendError;
        MscSCEPMessageUtils* messageUtils = [[MscSCEPMessageUtils alloc] init];
        MscSCEPResponse* response = [messageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_PKCSReq transaction:transaction error:&createAndSendError];
        if (createAndSendError) {
            @throw [MscSCEPLocalException exceptionWithCode:createAndSendError.code];
        }
        
        return response;
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
    }
}


-(MscSCEPResponse*)downloadCRLWithRSAKey:(MscRSAKey*)rsaKey certificate:(MscCertificate*)certificate issuer:(MscX509Name*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(MscSCEPError**)error {
    
    @try {
        
        NSAssert(rsaKey != nil, @"rsaKey parameter is missing");
        NSAssert(certificate != nil, @"certificate parameter is missing");
        NSAssert(issuer != nil, @"issuer parameter is missing");
        NSAssert(serial != nil, @"serial parameter is missing");
        NSAssert(caCertificate != nil, @"caCertificate parameter is missing");
        
        MscSCEPTransaction* transaction = [[MscSCEPTransaction alloc] init];
        transaction.scepServerURL = url;
        transaction.senderNonce = [NSString randomAlphanumericStringWithLength:16];
        transaction.transactionID = [NSString randomAlphanumericStringWithLength:16];
        
        transaction.signerKey = rsaKey;
        transaction.signerCertificate = certificate;
        transaction.caCertificate = caCertificate;
        transaction.issuerAndSerial = [[MscIssuerAndSerial alloc] init];
        transaction.issuerAndSerial.issuer = issuer;
        transaction.issuerAndSerial.serial = serial;
        
        MscSCEPError* createAndSendError;
        MscSCEPMessageUtils* messageUtils = [[MscSCEPMessageUtils alloc] init];
        MscSCEPResponse* response = [messageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_GetCRL transaction:transaction error:&createAndSendError];
        if (createAndSendError) {
            @throw [MscSCEPLocalException exceptionWithCode:createAndSendError.code];
        }
        
        return response;
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:FailedToDownloadCertificateRevocationList];
        }
        return nil;
    }
}

-(MscSCEPResponse*)downloadCertificateWithRSAKey:(MscRSAKey*)rsaKey issuer:(MscX509Name*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(MscSCEPError**)error {
    
    @try {
        
        NSAssert(rsaKey != nil, @"rsaKey parameter is missing");
        NSAssert(issuer != nil, @"issuer parameter is missing");
        NSAssert(serial != nil, @"serial parameter is missing");
        NSAssert(caCertificate != nil, @"caCertificate parameter is missing");
        
        //Generate selfsigned certificate
        MscX509Name* subject = [[MscX509Name alloc] init];
        subject.commonName = @"MscSCEP Library";
        subject.localityName = @"HU";
        
        NSError* x509Error;
        MscCertificateSigningRequest* csr = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:nil error:&x509Error];
        if (x509Error) {
            @throw [MscSCEPLocalException exceptionWithCode:x509Error.code];
        }
        
        [csr signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&x509Error];
        if (x509Error) {
           @throw [MscSCEPLocalException exceptionWithCode:x509Error.code];
        }
        
        MscCertificate* selfSignedCertificate = [[MscCertificate alloc] initWithRequest:csr error:&x509Error];
        if (x509Error) {
            @throw [MscSCEPLocalException exceptionWithCode:x509Error.code];
        }
        
        [selfSignedCertificate signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&x509Error];
        if (x509Error) {
            @throw [MscSCEPLocalException exceptionWithCode:x509Error.code];
        }
        
        MscSCEPTransaction* transaction = [[MscSCEPTransaction alloc] init];
        transaction.scepServerURL = url;
        transaction.senderNonce = [NSString randomAlphanumericStringWithLength:16];
        transaction.transactionID = [NSString randomAlphanumericStringWithLength:16];
        
        transaction.signerKey = rsaKey;
        transaction.signerCertificate = selfSignedCertificate;
        transaction.caCertificate = caCertificate;
        transaction.issuerAndSerial = [[MscIssuerAndSerial alloc] init];
        transaction.issuerAndSerial.issuer = issuer;
        transaction.issuerAndSerial.serial = serial;
        
        MscSCEPError* createAndSendError;
        MscSCEPMessageUtils* messageUtils = [[MscSCEPMessageUtils alloc] init];
        MscSCEPResponse* response = [messageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_GetCert transaction:transaction error:&createAndSendError];
        if (createAndSendError) {
            @throw [MscSCEPLocalException exceptionWithCode:createAndSendError.code];
        }
        
        return response;
        
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
    }
}

@end
