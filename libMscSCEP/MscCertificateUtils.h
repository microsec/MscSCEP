//
//  MscCertificateUtils.h
//  MscSCEP
//
//  Created by Microsec on 2014.02.12..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificate.h"
#import "MscCertificateSigningRequest.h"
#import "MscCertificateSubject.h"
#import <openssl/x509.h>

@interface MscCertificateUtils : NSObject

+(X509_NAME*)convertMscCertificateSubjectToX509_NAME:(MscCertificateSubject*)subject error:(NSError**)error;
+(MscCertificateSubject*)convertX509_NAMEToMscCertificateSubject:(X509_NAME*)name error:(NSError**)error;
+(NSString*)getCertificateSigningRequestPublicKeyFingerPrint:(MscCertificateSigningRequest*)request error:(NSError**)error;
+(NSString*)getCertificatePublicKeyFingerPrint:(MscCertificate*)certificate error:(NSError**)error;
+(NSString*)convertASN1_INTEGERToNSString:(ASN1_INTEGER*)serialNumber error:(NSError**)error;
+(ASN1_INTEGER*)convertNSStringToASN1_INTEGER:(NSString*)serialNumber error:(NSError**)error;
+(NSDate*)convertASN1_TIMEToNSDate:(ASN1_TIME*)asn1_time error:(NSError**)error;

@end
