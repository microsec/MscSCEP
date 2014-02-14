//
//  MscCertificateSigningRequest.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscCertificateSigningRequest.h"
#import "MscCertificateSigningRequestX509_REQ.h"
#import "NSString+MscExtensions.h"
#import "MscLocalException.h"
#import "MscRSAKeyRSA.h"
#import "MscCertificateUtils.h"

#import <openssl/x509.h>
#import <openssl/pem.h>

@implementation MscCertificateSigningRequest

@synthesize _request;

-(id)initWithSubject:(MscCertificateSubject*)subject rsaKey:(MscRSAKey*)rsaKey challengePassword:(NSString*)challengePassword fingerPrintAlgorithm:(FingerPrintAlgorithm)fingerPrintAlgorithm error:(NSError**)error{
    
    if (self = [super init]) {
    
        X509_REQ *request = NULL;
        X509_NAME *name = NULL;
        
        @try {
            
            int returnCode;
            
            if (!subject) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate signing request, subject parameter missing"}];
            }
            
            if (!rsaKey) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate signing request, rsaKey parameter missing"}];
            }
            
            if (!fingerPrintAlgorithm) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate certificate signing request, fingerPrintAlgorithm parameter missing"}];
            }
            
            request = X509_REQ_new();
            if (!request) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: request"}];
            }
            
            returnCode = X509_REQ_set_pubkey(request, rsaKey._evpkey);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate request, function X509_REQ_set_pubkey returned with %d", returnCode]}];
            }
            
            //Set DN
            NSError *error;
            name = [MscCertificateUtils convertMscCertificateSubjectToX509_NAME:subject error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            returnCode = X509_REQ_set_subject_name(request, name);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate request, function X509_REQ_set_subject_name returned with %d", returnCode]}];
            }
            
            if (challengePassword && ![challengePassword isEmpty]) {
                returnCode = X509_REQ_add1_attr_by_NID(request, NID_pkcs9_challengePassword, MBSTRING_UTF8, (const unsigned char*)[challengePassword UTF8String], -1);
                if (returnCode != 1) {
                    @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate request, function X509_REQ_add1_attr_by_NID returned with %d", returnCode]}];
                }
            }
            
            returnCode = X509_REQ_sign(request, rsaKey._evpkey, EVP_get_digestbyname([[self getFingerPrintAlgorithmNameByEnum:fingerPrintAlgorithm] ASCIIString]));
            if (returnCode == 0) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateRequest errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate request, function X509_REQ_sign returned with %d", returnCode]}];
            }
            
            
            
            _request = request;
            
            return self;
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            X509_REQ_free(request);
            return nil;
        }
    }
    return nil;
}

-(id)initWithContentsOfFile:(NSString *)path error:(NSError **)error {
    
    if (self = [super init]) {
        FILE* file;
        X509_REQ *request = NULL;
        
        @try {
            
            file = fopen([path fileSystemRepresentation], "r");
            if (!file) {
                @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for read: %@", path]}];
            }
            
            request = PEM_read_X509_REQ(file, NULL, NULL, NULL);
            if (!request) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadRequest errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read key file"}];
            }
            _request = request;
            return self;
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            X509_REQ_free(request);
            return nil;
        }
        @finally {
            
            fclose(file);
        }
    }
    return nil;
}

-(void)saveToPath:(NSString *)path error:(NSError **)error {
    
    FILE* file;
    
    @try {
        
        int returnCode;
        
        file = fopen([path fileSystemRepresentation], "w");
        if (!file) {
            @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for write: %@", path]}];
        }
        
        returnCode = PEM_write_X509_REQ(file, _request);
        if (returnCode != 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToWriteRequest errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to write request file, function PEM_write_X509_REQ returned with %d", returnCode]}];
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

-(NSString*)getFingerPrintAlgorithmNameByEnum: (FingerPrintAlgorithm)fingerPrintAlgorithm {
    switch (fingerPrintAlgorithm) {
        case FingerPrintAlgorithm_MD5:
            return @"MD5";
            break;
        case FingerPrintAlgorithm_SHA1:
            return @"SHA1";
            break;
        case FingerPrintAlgorithm_SHA256:
            return @"SHA256";
            break;
        case FingerPrintAlgorithm_SHA512:
            return @"SHA512";
            break;
    }
}

-(void)dealloc {
    X509_REQ_free(_request);
}

@end
