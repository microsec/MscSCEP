//
//  MscCertificate.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificateSigningRequest.h"
#import "MscCertificateRevocationList.h"

#define SELFSIGNED_EXPIRE_DAYS  365

@interface MscCertificate : NSObject

-(MscCertificate*) init __attribute__((unavailable("please, use initWithRequest or initWithContentsOfFile for initialization")));

-(id)initWithRequest:(MscCertificateSigningRequest*)request rsaKey:(MscRSAKey*)rsaKey error:(NSError**)error;
-(id)initWithContentsOfFile:(NSString*)path error:(NSError**)error;
-(void)saveToPath:(NSString*)path error:(NSError**)error;

-(MscCertificateSubject*)getSubjectWithError:(NSError**)error;
-(MscCertificateSubject*)getIssuerWithError:(NSError**)error;
-(NSString*)getSerialWithError:(NSError**)error;
-(NSDate*)getNotBeforeWithError:(NSError**)error;
-(NSDate*)getNotAfterWithError:(NSError**)error;

@end
