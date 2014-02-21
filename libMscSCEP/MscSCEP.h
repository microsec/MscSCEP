//
//  MscSCEP.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.13..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscRSAKey.h"
#import "MscCertificate.h"
#import "MscSCEPResponse.h"

@interface MscSCEP : NSObject

-(MscSCEP*) init __attribute__((unavailable("please, use initWithURL for initialization")));
-(id)initWithURL:(NSURL*)_url;

-(NSArray*)downloadCACertificate:(NSError**)error;
-(MscSCEPResponse*)enrolWithRSAKey:(MscRSAKey*)rsaKey certificateSigningRequest:(MscCertificateSigningRequest*)certificateSigningRequest certificate:(MscCertificate*)certificate caCertificate:(MscCertificate*)caCertificate createPKCS12:(BOOL)createPKCS12 pkcs12Password:(NSString*)pkcs12Password error:(NSError**)error;
-(MscSCEPResponse*)downloadCRLWithRSAKey:(MscRSAKey*)rsaKey certificate:(MscCertificate*)certificate issuer:(MscCertificateSubject*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(NSError**)error;
-(MscSCEPResponse*)downloadCertificateWithRSAKey:(MscRSAKey*)rsaKey issuer:(MscCertificateSubject*)issuer serial:(NSString*)serial caCertificate:(MscCertificate*)caCertificate error:(NSError**)error;

@end
