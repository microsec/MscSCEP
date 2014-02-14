//
//  MscIssuerAndSerial.h
//  MscSCEP
//
//  Created by Microsec on 2014.02.07..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificateSubject.h"

@interface MscIssuerAndSerial : NSObject

@property MscCertificateSubject* issuer;
@property NSString* serial;

@end
