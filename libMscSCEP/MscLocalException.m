//
//  MscLocalException.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.23..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscLocalException.h"

@implementation MscLocalException {
    
    @private
    NSString* _errorDomain;
    NSUInteger _errorCode;
    NSDictionary* _errorUserInfo;
}

@synthesize errorDomain = _errorDomain, errorCode = _errorCode, errorUserInfo = _errorUserInfo;

-(id)initWithErrorCode:(NSUInteger)errorCode errorUserInfo:(NSDictionary*)errorUserInfo {
    if (self = [super initWithName:@"MscLocalException" reason:nil userInfo:nil]) {

        _errorDomain = @"hu.microsec.mscscep";
        _errorCode = errorCode;
        _errorUserInfo = errorUserInfo;
        
        return self;
    } else {
        return nil;
    }
}

@end
