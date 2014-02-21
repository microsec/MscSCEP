//
//  MscCertificateRevocationList.m
//  MscSCEP
//
//  Created by Microsec on 2014.02.07..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscCertificateRevocationList.h"
#import "MscCertificateRevocationList_OpenSSL_X509_CRL.h"
#import "MscLocalException.h"

#import "NSString+MscExtensions.h"
#import <openssl/pem.h>

@implementation MscCertificateRevocationList

@synthesize _crl;

-(id)initWithX509_CRL:(X509_CRL *)crl {
    
    if (self = [super init]) {
        _crl = crl;
        return self;
    }
    return nil;
}

-(id)initWithContentsOfFile:(NSString*)path error:(NSError**)error {
    
    if (self = [super init]) {
        FILE* file;
        X509_CRL *crl = NULL;
        
        @try {
            
            file = fopen([path fileSystemRepresentation], "r");
            if (!file) {
                @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for read: %@", path]}];
            }
            
            crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
            if (!crl) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read certificate revocation list file"}];
            }
            _crl = crl;
            return self;
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            X509_CRL_free(crl);
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
        
        returnCode = PEM_write_X509_CRL(file, _crl);
        if (returnCode != 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToWriteCertificateRevocationList errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to write certificate revocation list file, function PEM_write_X509_CRL returned with %d", returnCode]}];
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

-(void)dealloc {
    
    X509_CRL_free(_crl);
}

@end
