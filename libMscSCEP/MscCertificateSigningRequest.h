//
//  MscCertificateSigningRequest.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificateSubject.h"
#import "MscRSAKey.h"

typedef NS_ENUM(NSUInteger, FingerPrintAlgorithm) {
    FingerPrintAlgorithm_MD5,
    FingerPrintAlgorithm_SHA1,
    FingerPrintAlgorithm_SHA256,
    FingerPrintAlgorithm_SHA512
};

@interface MscCertificateSigningRequest : NSObject

-(MscCertificateSigningRequest*) init __attribute__((unavailable("please, use initWithSubject or initWithContentsOfFile for initialization")));
-(id)initWithSubject:(MscCertificateSubject*)subject rsaKey:(MscRSAKey*)rsaKey challengePassword:(NSString*)challengePassword fingerPrintAlgorithm:(FingerPrintAlgorithm)fingerPrintAlgorithm error:(NSError**)error;
-(id)initWithContentsOfFile:(NSString*)path error:(NSError**)error;
-(void)saveToPath:(NSString *)path error:(NSError **)error;

@end
