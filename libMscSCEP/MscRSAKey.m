//
//  MscRSAKey.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscRSAKey.h"
#import "MscRSAKey_OpenSSL_RSA.h"
#import "MscLocalException.h"
#import "NSString+MscExtensions.h"

#import <openssl/rsa.h>
#import <openssl/pem.h>

@implementation MscRSAKey

@synthesize _rsa, _evpkey;

-(id)initWithKeySize:(KeySize)keySize error:(NSError**)error {
    
    if (self = [super init]) {
        BIGNUM *bigNumber = NULL;
        RSA *rsa = NULL;
        EVP_PKEY* evpkey = NULL;
        
        @try {
        
            int returnCode;
        
            if (!keySize) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateKey errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to generate RSA key, keySize parameter missing"}];
            }
        
            bigNumber = BN_new();
            if (!bigNumber) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: bigNumber"}];
            }
        
            rsa = RSA_new();
            if (!rsa) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: rsa"}];
            }
        
            returnCode = BN_set_word(bigNumber, RSA_F4);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateKey errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate RSA key, function BN_set_word returned with %d", returnCode]}];
            }
        
            returnCode = RSA_generate_key_ex(rsa, keySize, bigNumber, NULL);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateKey errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate RSA key, function RSA_generate_key_ex returned with %d", returnCode]}];
            }
            
            evpkey = EVP_PKEY_new();
            if (!evpkey) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: evpkey"}];
            }
            
            returnCode = EVP_PKEY_set1_RSA(evpkey, rsa);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateKey errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate RSA key, function EVP_PKEY_assign_RSA returned with %d", returnCode]}];
            }
            
            _rsa = rsa;
            _evpkey = evpkey;
            
            return self;
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            RSA_free(rsa);
            EVP_PKEY_free(evpkey);
            return nil;
        }
        @finally {
            
            BN_free(bigNumber);
        }
    }
    return nil;
}

-(id)initWithContentsOfFile:(NSString *)path error:(NSError **)error {
    
    if (self = [super init]) {
        FILE* file = NULL;
        RSA *rsa = NULL;
        EVP_PKEY* evpkey = NULL;
        
        @try {
            
            int returnCode;
            
            file = fopen([path fileSystemRepresentation], "r");
            if (!file) {
                @throw [[MscLocalException alloc] initWithErrorCode:IOError errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to open file for read: %@", path]}];
            }
            
            rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            if (!rsa) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadKeyFile errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to read key file"}];
            }
            _rsa = rsa;
            
            evpkey = EVP_PKEY_new();
            if (!evpkey) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: evpkey"}];
            }
            
            returnCode = EVP_PKEY_set1_RSA(evpkey, _rsa);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToGenerateKey errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to generate RSA key, function EVP_PKEY_assign_RSA returned with %d", returnCode]}];
            }
            _evpkey = evpkey;
            
            return self;
        }
        @catch (MscLocalException *e) {
            
            if (error) {
                *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
            }
            RSA_free(rsa);
            EVP_PKEY_free(evpkey);
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
        
        returnCode = PEM_write_RSAPrivateKey(file, _rsa, NULL, NULL, 0, NULL, NULL);
        if (returnCode != 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToWriteKeyFile errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to write key file, function PEM_write_RSAPrivateKey returned with %d", returnCode]}];
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
    RSA_free(_rsa);
    EVP_PKEY_free(_evpkey);
}

@end
