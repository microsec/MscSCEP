//
//  MscSCEPResponse.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.29..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEPResponse.h"
#import "MscSCEPResponsePrivate.h"
#import "MscLocalException.h"
#import "MscSCEPMessageUtils.h"

@implementation MscSCEPResponse

@synthesize messageType, pkiStatus, failInfo, certificates, certificateRevocationLists, transaction, pkcs12;

-(void)pollWithError:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        MscSCEPResponse* response = [MscSCEPMessageUtils createAndSendSCEPMessageWithMessageType:SCEPMessage_GetCertInitial transaction:transaction error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        messageType = response.messageType;
        pkiStatus = response.pkiStatus;
        failInfo = response.failInfo;
        certificates = response.certificates;
        certificateRevocationLists = response.certificateRevocationLists;
        transaction = response.transaction;
        pkcs12 = response.pkcs12;
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
    }
}

@end
