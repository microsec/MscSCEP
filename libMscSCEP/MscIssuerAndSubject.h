//
//  MscIssuerAndSubject.h
//  MscSCEP
//
//  Created by Microsec on 2014.02.07..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificateSubject.h"

@interface MscIssuerAndSubject : NSObject

@property MscCertificateSubject* issuer;
@property MscCertificateSubject* subject;

@end
