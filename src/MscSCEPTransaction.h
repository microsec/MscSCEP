//
//  MscSCEPTransaction.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.29..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscX509Common/MscCertificate.h"
#import "MscX509Common/MscRSAKey.h"
#import "MscX509Common/MscX509Name.h"
#import "MscX509Common/MscCertificateSigningRequest.h"
#import "MscX509Common/MscIssuerAndSubject.h"
#import "MscX509Common/MscIssuerAndSerial.h"

@interface MscSCEPTransaction : NSObject<NSCoding>

@property NSString* transactionID;
@property NSString* senderNonce;
@property MscCertificateSigningRequest* certificateSigningRequest;
@property MscCertificate* signerCertificate;
@property MscRSAKey* signerKey;
@property MscCertificate* caCertificate;
@property MscIssuerAndSubject* issuerAndSubject;
@property MscIssuerAndSerial* issuerAndSerial;
@property NSURL* scepServerURL;
@property BOOL createPKCS12;
@property NSString* pkcs12Password;

@end
