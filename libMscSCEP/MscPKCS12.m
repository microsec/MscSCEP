//
//  MscPKCS12.m
//  MscSCEP
//
//  Created by Microsec on 2014.02.18..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscPKCS12.h"
#import <openssl/pkcs12.h>
#import "MscLocalException.h"
#import "MscPKCS12_OpenSSL_PKCS12.h"
#import "MscCertificate_OpenSSL_X509.h"

@implementation MscPKCS12

@synthesize _pkcs12;

-(id)initWithPKCS12:(PKCS12*)pkcs12 {
    
    if (self = [super init]) {
        _pkcs12 = pkcs12;
        return self;
    }
    return nil;
}

-(id)initWithContentsOfFile:(NSString *)path error:(NSError **)error {
    
    if (self = [super init]) {
        FILE* file = NULL;
        PKCS12 *pkcs12 = NULL;
        
        @try {
            
            file = fopen([path fileSystemRepresentation], "r");
            if (!file) {
                @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for read: %@", path]}];
            }
            
            pkcs12 =  d2i_PKCS12_fp(file, NULL);
            if (!pkcs12) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadPKCS12File errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read PKCS12 file"}];
            }
            _pkcs12 = pkcs12;
            
            return self;
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            PKCS12_free(pkcs12);
            return nil;
        }
        @finally {
            fclose(file);
        }
    }
    return nil;
}

-(void)saveToPath:(NSString *)path error:(NSError **)error {
    
    FILE* file = NULL;
    
    @try {
        
        int returnCode;
        
        file = fopen([path fileSystemRepresentation], "w");
        if (!file) {
            @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for write: %@", path]}];
        }
        
        returnCode = i2d_PKCS12_fp(file, _pkcs12);
        if (returnCode != 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToWritePKCS12File errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to write PKCS12 file, function i2d_PKCS12_fp returned with %d", returnCode]}];
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

-(MscCertificate*)getCertificateWithPassword:(NSString*)password error:(NSError**)error {
    
    X509* certificate = NULL;
    
    @try {
        
        int returnCode;
        returnCode = PKCS12_parse(_pkcs12, [password UTF8String], NULL, &certificate, NULL);
        if (returnCode != 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToParsePKCS12File errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to parse PKCS12 file, function PKCS12_parse returned with %d", returnCode]}];
        }
        return [[MscCertificate alloc] initWithX509:certificate];
    }
    @catch (MscLocalException *e) {
        
        X509_free(certificate);
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

@end
