//
//  MscSCEPResponse.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.29..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, SCEPMessage) {
    SCEPMessage_None            = 0,
    SCEPMessage_CertRep         = 3,
    SCEPMessage_PKCSReq         = 19,
    SCEPMessage_GetCertInitial  = 20,
    SCEPMessage_GetCert         = 21,
    SCEPMessage_GetCRL          = 22
};

typedef NS_ENUM(NSUInteger, SCEPPKIStatus) {
    SCEPPKIStatus_SUCCESS   = 0,
    SCEPPKIStatus_FAILURE   = 2,
    SCEPPKIStatus_PENDING   = 3
};

typedef NS_ENUM(NSUInteger, SCEPFailInfo) {
    SCEPFailInfo_BadAlg             = 0,
    SCEPFailInfo_BadMessageCheck    = 1,
    SCEPFailInfo_BadRequest         = 2,
    SCEPFailInfo_BadTime            = 3,
    SCEPFailInfo_BadCertId          = 4,
    SCEPFailInfo_NoError            = 1000
};

#define MIME_GETCA      @"application/x-x509-ca-cert"
#define MIME_GETCA_RA   @"application/x-x509-ca-ra-cert"
#define MIME_PKI        @"application/x-pki-message"

@interface MscSCEPResponse : NSObject

@property SCEPMessage messageType;
@property SCEPPKIStatus pkiStatus;
@property SCEPFailInfo failInfo;
@property NSArray* certificates;
@property NSArray* certificateRevocationLists;

-(void)pollWithError:(NSError**)error;

@end
