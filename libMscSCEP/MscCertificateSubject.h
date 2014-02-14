//
//  MscCertificateSubject.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.14..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MscCertificateSubject : NSObject

@property NSString* commonName;
@property NSString* localityName;
@property NSString* stateOrProvinceName;
@property NSString* organizationName;
@property NSString* organizationalUnitName;
@property NSString* countryName;
@property NSString* streetAddress;
@property NSString* domainComponent;
@property NSString* userid;

@end
