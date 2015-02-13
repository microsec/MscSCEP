//
//  MscSCEPError.m
//  MscSCEP
//
//  Created by Microsec on 2014.08.08..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEPError.h"

@implementation MscSCEPError

+(id)errorWithCode:(NSInteger)code {
    
    return [MscSCEPError errorWithDomain:@"hu.microsec.scep" code:code userInfo:nil];
}

@end
