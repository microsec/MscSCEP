//
//  MscSCEPResponse.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.29..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEPResponse.h"
#import "MscSCEPResponsePrivate.h"
#import "MscSCEPLocalException.h"
#import "MscSCEPMessageUtils.h"
#import <openssl/evp.h>

@implementation MscSCEPResponse

@synthesize messageType, pkiStatus, failInfo, certificates, certificateRevocationLists, transaction, pkcs12;

-(void)pollWithError:(MscSCEPError**)error {
    
    
    @try {
        OpenSSL_add_all_algorithms();
        
        MscSCEPError* pollError;
        MscSCEPMessageUtils* messageUtils = [[MscSCEPMessageUtils alloc] init];
        MscSCEPResponse* response = [messageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_GetCertInitial transaction:transaction error:&pollError];
        
        if (pollError) {
            @throw [MscSCEPLocalException exceptionWithCode:pollError.code];
        }
        
        messageType = response.messageType;
        pkiStatus = response.pkiStatus;
        failInfo = response.failInfo;
        certificates = response.certificates;
        certificateRevocationLists = response.certificateRevocationLists;
        transaction = response.transaction;
        pkcs12 = response.pkcs12;
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
    }
}

- (void)encodeWithCoder:(NSCoder *)aCoder {
    
    [aCoder encodeInteger:messageType forKey:@"messageType"];
    [aCoder encodeInteger:pkiStatus forKey:@"pkiStatus"];
    [aCoder encodeInteger:failInfo forKey:@"failInfo"];
    [aCoder encodeObject:certificates forKey:@"certificates"];
    [aCoder encodeObject:certificateRevocationLists forKey:@"certificateRevocationLists"];
    [aCoder encodeObject:transaction forKey:@"transaction"];
    [aCoder encodeObject:pkcs12 forKey:@"pkcs12"];

}

- (id)initWithCoder:(NSCoder *)aDecoder {
    
    if (self = [super init]) {
        
        messageType = [aDecoder decodeIntegerForKey:@"messageType"];
        pkiStatus = [aDecoder decodeIntegerForKey:@"pkiStatus"];
        failInfo = [aDecoder decodeIntegerForKey:@"failInfo"];
        certificates = [aDecoder decodeObjectForKey:@"certificates"];
        certificateRevocationLists = [aDecoder decodeObjectForKey:@"certificateRevocationLists"];
        transaction = [aDecoder decodeObjectForKey:@"transaction"];
        pkcs12 = [aDecoder decodeObjectForKey:@"pkcs12"];
        
        return self;
    }
    return nil;
}

@end
