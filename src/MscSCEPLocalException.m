//
//  MscLocalException.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.23..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEPLocalException.h"

@implementation MscSCEPLocalException

@synthesize errorCode = _errorCode;

-(id)initWithErrorCode:(NSUInteger)errorCode {
    
    self = [super initWithName:@"MscSCEPLocalException" reason:nil userInfo:nil];
    if (self) {
        
        _errorCode = errorCode;
    }
    return self;
}

+(id)exceptionWithCode:(NSUInteger)code {
    
    return [[MscSCEPLocalException alloc] initWithErrorCode:code];
}

@end
