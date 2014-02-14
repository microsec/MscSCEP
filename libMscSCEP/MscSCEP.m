//
//  MscSCEP.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.13..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEP.h"

#import "MscLocalException.h"
#import "MscCertificateX509.h"
#import "MscCertificateUtils.h"
#import "MscSCEPMessageUtils.h"

#import "NSString+MscExtensions.h"

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

-(NSArray*)downloadCACertificate:(NSError**)error {
    
    PKCS7* pkcs7 = NULL;
    
    @try {
        
        NSURL* getCAURL = [NSURL URLWithString: [NSString stringWithFormat:@"%@?operation=GetCACert&message=%@", [url absoluteString], @"CAIdentifier"]];
        
        NSURLRequest* getCARequest = [NSURLRequest requestWithURL:getCAURL];
                           
        NSData *payLoad;
        NSURLResponse* response;
        NSError* error;

        payLoad = [NSURLConnection sendSynchronousRequest:getCARequest returningResponse:&response error:&error];
        
        if ([[response MIMEType] isEqual: MIME_GETCA]) {
            
            //it should be a DER encoded X.509 object
            const unsigned char* payLoadData = [payLoad bytes];
            X509* caCertificate = d2i_X509(NULL, &payLoadData, [payLoad length]);
            if (!caCertificate) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read server certificate, function d2i_X509 returned with null"}];
            }
            
            return [NSArray arrayWithObject:[[MscCertificate alloc] initWithX509:caCertificate]];
        }
        else if ([[response MIMEType] isEqual: MIME_GETCA_RA]) {
            
            //it should be a DER encoded PKCS7 object
            const unsigned char* payLoadData = [payLoad bytes];
            
            pkcs7 = d2i_PKCS7(NULL, &payLoadData, [payLoad length]);
            if (!pkcs7) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read server certificate, function d2i_PKCS7 returned with null"}];
            }
            
            if (OBJ_obj2nid(pkcs7->type) != NID_pkcs7_signed) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCACertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download server certificate, pkcs7 obejct type is not pkcs7_signed"}];
            }
            
            STACK_OF(X509) *caCertificates = pkcs7->d.sign->cert;
            
            if (!caCertificates) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCACertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download server certificate, certificates are missing from pkcs7 object"}];
            }
            
            NSMutableArray* certificates = [[NSMutableArray alloc] initWithCapacity:sk_X509_num(caCertificates)];
            for (int i = 0; i < sk_X509_num(caCertificates); i++) {
                X509* cert = X509_dup(sk_X509_value(caCertificates, i));
                [certificates addObject:[[MscCertificate alloc] initWithX509: cert]];
            }
            
            return certificates;
        }
        else {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCACertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download server certificate, mime type of server response is wrong."}];
            return nil;
        }
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
    @finally {
        
        if (pkcs7) PKCS7_free(pkcs7);
    }
}

-(MscSCEPResponse*)enrolWithRSAKey:(MscRSAKey*)rsaKey certificateSigningRequest:(MscCertificateSigningRequest*)certificateSigningRequest certificate:(MscCertificate*)certificate caCertificate:(MscCertificate*)caCertificate error:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        if (!rsaKey) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEnrolCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to enrol certificate, rsaKey parameter is missing"}];
        }
        if (!certificateSigningRequest) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEnrolCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to enrol certificate, certificateSigningRequest parameter is missing"}];
        }
        if (!certificate) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEnrolCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to enrol certificate, certificate parameter is missing"}];
        }
        if (!caCertificate) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEnrolCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to enrol certificate, aCertificate parameter is missing"}];
        }
        
        MscSCEPTransaction* transaction = [[MscSCEPTransaction alloc] init];
        transaction.scepServerURL = url;
        transaction.senderNonce = [NSString randomAlphanumericStringWithLength:16];
        transaction.transactionID = [MscCertificateUtils getCertificatePublicKeyFingerPrint:certificate error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        transaction.signerKey = rsaKey;
        transaction.signerCertificate = certificate;
        transaction.caCertificate = caCertificate;
        transaction.certificateSigningRequest = certificateSigningRequest;
        
        MscSCEPResponse* response = [MscSCEPMessageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_PKCSReq transaction:transaction error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return response;
        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}


-(MscSCEPResponse*)downloadCRLWithRSAKey:(MscRSAKey*)rsaKey certificate:(MscCertificate*)certificate issuer:(MscCertificateSubject*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        if (!rsaKey) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate revocation list, rsaKey parameter is missing"}];
        }
        if (!certificate) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate revocation list, certificate parameter is missing"}];
        }
        if (!issuer) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate revocation list, issuer parameter is missing"}];
        }
        if (!serial) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate revocation list, serial parameter is missing"}];
        }
        if (!caCertificate) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate revocation list, caCertificate parameter is missing"}];
        }
        
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
        
        MscSCEPResponse* response = [MscSCEPMessageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_GetCRL transaction:transaction error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return response;
        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

-(MscSCEPResponse*)downloadCertificateWithRSAKey:(MscRSAKey*)rsaKey issuer:(MscCertificateSubject*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        if (!rsaKey) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate, rsaKey parameter is missing"}];
        }
        if (!issuer) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate, rsaKey parameter is missing"}];
        }
        if (!serial) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate, rsaKey parameter is missing"}];
        }
        if (!caCertificate) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDownloadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to download certificate, rsaKey parameter is missing"}];
        }
        
        //Generate selfsigned certificate
        MscCertificateSubject* subject = [[MscCertificateSubject alloc] init];
        subject.commonName = @"MscSCEP Library";
        subject.localityName = @"HU";
        MscCertificateSigningRequest* csr = [[MscCertificateSigningRequest alloc] initWithSubject:subject rsaKey:rsaKey challengePassword:nil fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&error];
        if (nil != error) {
           @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        MscCertificate* selfSignedCertificate = [[MscCertificate alloc] initWithRequest:csr rsaKey:rsaKey error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
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
        
        MscSCEPResponse* response = [MscSCEPMessageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_GetCert transaction:transaction error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return response;
        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

@end
