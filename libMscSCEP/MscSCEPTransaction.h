//
//  MscSCEPTransaction.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.29..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificate.h"
#import "MscRSAKey.h"
#import "MscCertificateSubject.h"
#import "MscCertificateSigningRequest.h"
#import "MscIssuerAndSubject.h"
#import "MscIssuerAndSerial.h"

@interface MscSCEPTransaction : NSObject

@property NSString* transactionID;
@property NSString* senderNonce;
@property MscCertificateSigningRequest* certificateSigningRequest;
@property MscCertificate* signerCertificate;
@property MscRSAKey* signerKey;
@property MscCertificate* caCertificate;
@property MscIssuerAndSubject* issuerAndSubject;
@property MscIssuerAndSerial* issuerAndSerial;
@property NSURL* scepServerURL;

@end
