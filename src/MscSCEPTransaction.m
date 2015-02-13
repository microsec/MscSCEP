//
//  MscSCEPTransaction.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.29..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MSCSCEPTransaction.h"

@implementation MscSCEPTransaction

@synthesize transactionID, senderNonce, certificateSigningRequest, signerCertificate, signerKey, caCertificate, issuerAndSerial, issuerAndSubject, scepServerURL, createPKCS12, pkcs12Password;

- (void)encodeWithCoder:(NSCoder *)aCoder {
    
    [aCoder encodeObject:transactionID forKey:@"transactionID"];
    [aCoder encodeObject:senderNonce forKey:@"senderNonce"];
    [aCoder encodeObject:certificateSigningRequest forKey:@"certificateSigningRequest"];
    [aCoder encodeObject:signerCertificate forKey:@"signerCertificate"];
    [aCoder encodeObject:signerKey forKey:@"signerKey"];
    [aCoder encodeObject:caCertificate forKey:@"caCertificate"];
    [aCoder encodeObject:issuerAndSerial forKey:@"issuerAndSerial"];
    [aCoder encodeObject:issuerAndSubject forKey:@"issuerAndSubject"];
    [aCoder encodeObject:scepServerURL forKey:@"scepServerURL"];
    [aCoder encodeBool:createPKCS12 forKey:@"createPKCS12"];
    [aCoder encodeObject:pkcs12Password forKey:@"pkcs12Password"];
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    
    if (self = [super init]) {
        
        transactionID = [aDecoder decodeObjectForKey:@"transactionID"];
        senderNonce = [aDecoder decodeObjectForKey:@"senderNonce"];
        certificateSigningRequest = [aDecoder decodeObjectForKey:@"certificateSigningRequest"];
        signerCertificate = [aDecoder decodeObjectForKey:@"signerCertificate"];
        signerKey = [aDecoder decodeObjectForKey:@"signerKey"];
        caCertificate = [aDecoder decodeObjectForKey:@"caCertificate"];
        issuerAndSerial = [aDecoder decodeObjectForKey:@"issuerAndSerial"];
        issuerAndSubject = [aDecoder decodeObjectForKey:@"issuerAndSubject"];
        scepServerURL = [aDecoder decodeObjectForKey:@"scepServerURL"];
        createPKCS12 = [aDecoder decodeBoolForKey:@"createPKCS12"];
        pkcs12Password = [aDecoder decodeObjectForKey:@"pkcs12Password"];
        
        return self;
    }
    return nil;
}

@end
