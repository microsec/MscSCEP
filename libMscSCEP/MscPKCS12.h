//
//  MscPKCS12.h
//  MscSCEP
//
//  Created by Microsec on 2014.02.18..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscCertificate.h"

@interface MscPKCS12 : NSObject

-(MscPKCS12*) init __attribute__((unavailable("please, use initWithContentsOfFile for initialization")));
-(id)initWithContentsOfFile:(NSString*)path error:(NSError**)error;
-(void)saveToPath:(NSString *)path error:(NSError **)error;
-(MscCertificate*)getCertificateWithPassword:(NSString*)password error:(NSError**)error;

@end
