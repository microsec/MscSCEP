//
//  MscCertificate.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscCertificate.h"
#import "MscCertificate_OpenSSL_X509.h"
#import "NSString+MscExtensions.h"
#import "MscLocalException.h"
#import "MscCertificateSigningRequest_OpenSSL_X509_REQ.h"
#import "MscRSAKey_OpenSSL_RSA.h"
#import "MscCertificateUtils.h"
#import <openssl/pem.h>

#define SELFSIGNED_EXPIRE_DAYS 365

@implementation MscCertificate

@synthesize _x509;

-(id)initWithX509:(X509 *)x509 {
    
    if (self = [super init]) {
        _x509 = x509;
        return self;
    }
    return nil;
}

-(id)initWithRequest:(MscCertificateSigningRequest*)request rsaKey:(MscRSAKey*)rsaKey error:(NSError**)error {
    
    if (self = [super init]) {
        
        ASN1_INTEGER* serial = NULL;
        X509* selfSignedCertificate = NULL;
        
        @try {
            
            int returnCode;
            
            if (!request) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate, request parameter missing"}];
            }
            
            if (!rsaKey) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate, rsaKey parameter is missing"}];
            }
            
            EVP_PKEY* publicKey = NULL;
            if(!(publicKey = X509_REQ_get_pubkey(request._request))) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to enroll certificate, function: X509_REQ_get_pubkey"}];
            }
            
            X509_NAME* subject = X509_REQ_get_subject_name(request._request);
            if(!subject) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate, function: X509_REQ_get_subject_name"}];
            }
            
            selfSignedCertificate = X509_new();
            if(!selfSignedCertificate) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: selfSignedCertificate"}];
            }
            
            returnCode = X509_set_version(selfSignedCertificate, 2L);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate certificate, function X509_set_version returned with: %d", returnCode ] }];
            }
            
            NSError* error;
            NSString* serialNumber = [MscCertificateUtils getCertificateSigningRequestPublicKeyFingerPrint:request error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            serial = [MscCertificateUtils convertNSStringToASN1_INTEGER:serialNumber error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            returnCode = X509_set_serialNumber(selfSignedCertificate, serial);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate certificate, function X509_set_serialNumber returned with: %d", returnCode ] }];
            }
            
            returnCode = X509_set_subject_name(selfSignedCertificate, subject);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate certificate, function X509_set_subject_name returned with: %d", returnCode ] }];
            }
            
            returnCode = X509_set_issuer_name(selfSignedCertificate, subject);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate certificate, function X509_set_issuer_name returned with: %d", returnCode ] }];
            }
            
            returnCode = X509_set_pubkey(selfSignedCertificate, publicKey);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate certificate, function X509_set_pubkey returned with: %d", returnCode ] }];
            }
            
            if (!X509_gmtime_adj(X509_get_notBefore(selfSignedCertificate), 0)) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate, function: X509_gmtime_adj"}];
            }
            if (!X509_gmtime_adj(X509_get_notAfter(selfSignedCertificate), SELFSIGNED_EXPIRE_DAYS * 24 * 60)) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate, function: X509_gmtime_adj"}];
            }
            
            returnCode = X509_sign(selfSignedCertificate, rsaKey._evpkey, EVP_get_digestbyobj(request._request->sig_alg->algorithm));
            
            if (!returnCode) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate certificate, function X509_sign returned with: %d", returnCode ] }];
            }
            
            return [[MscCertificate alloc] initWithX509:selfSignedCertificate];
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            ASN1_INTEGER_free(serial);
            X509_free(selfSignedCertificate);
            return nil;
        }
    }
    return nil;
}

-(id)initWithContentsOfFile:(NSString*)path error:(NSError**)error {
    
    if (self = [super init]) {
        FILE* file;
        X509 *x509 = NULL;
    
        @try {
        
            file = fopen([path fileSystemRepresentation], "r");
            if (!file) {
                @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for read: %@", path]}];
            }
        
            x509 = PEM_read_X509(file, NULL, NULL, NULL);
            if (!x509) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate file"}];
            }
            _x509 = x509;
            return self;
        }
        @catch (MscLocalException *e) {
        
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            X509_free(x509);
            return nil;
        }
        @finally {
        
            fclose(file);
        }
    }
    return nil;
}

-(void)saveToPath:(NSString*)path error:(NSError**)error {
    
    FILE* file;
    
    @try {
        
        int returnCode;
        
        file = fopen([path fileSystemRepresentation], "w");
        if (!file) {
            @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for write: %@", path]}];
        }
        
        returnCode = PEM_write_X509(file, _x509);
        if (returnCode != 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToWriteCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to write certificate file, function PEM_write_X509 returned with %d", returnCode]}];
        }
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return;
    }
    @finally {
        
        fclose(file);
    }
}

-(MscCertificateSubject*)getSubjectWithError:(NSError**)error {
    
    X509_NAME* subjectName = NULL;
    
    @try {
        
        subjectName = X509_get_subject_name(_x509);
        if (!subjectName) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate, function: X509_get_subject_name"}];
        }
        
        NSError* error;
        MscCertificateSubject* subject = [MscCertificateUtils convertX509_NAMEToMscCertificateSubject:subjectName error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return subject;
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

-(MscCertificateSubject*)getIssuerWithError:(NSError**)error {
    
    X509_NAME* issuerName = NULL;
    
    @try {
        
        issuerName = X509_get_issuer_name(_x509);
        if (!issuerName) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate, function: X509_get_issuer_name"}];
        }
        
        NSError* error;
        MscCertificateSubject* issuer = [MscCertificateUtils convertX509_NAMEToMscCertificateSubject:issuerName error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return issuer;
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

-(NSString*)getSerialWithError:(NSError**)error {
    
    @try {
        
        ASN1_INTEGER* serialNumber = X509_get_serialNumber(_x509);
        if (!serialNumber) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate, function: X509_get_serialNumber"}];
        }
        
        NSError* error;
        NSString* serial = [MscCertificateUtils convertASN1_INTEGERToNSString:serialNumber error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return serial;

    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

-(NSDate*)getNotBeforeWithError:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        ASN1_TIME* notBeforeASN1_TIME = X509_get_notBefore(_x509);
        if (!notBeforeASN1_TIME) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate, function: X509_get_notBefore"}];
        }
        
        NSDate* notBefore = [MscCertificateUtils convertASN1_TIMEToNSDate:notBeforeASN1_TIME error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        return notBefore;
        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

-(NSDate*)getNotAfterWithError:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        ASN1_TIME* notAfterASN1_TIME = X509_get_notAfter(_x509);
        if (!notAfterASN1_TIME) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate, function: X509_get_notAfter"}];
        }
        
        NSDate* notAfter = [MscCertificateUtils convertASN1_TIMEToNSDate:notAfterASN1_TIME error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        return notAfter;
        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

-(void)dealloc {
    X509_free(_x509);
}

@end
