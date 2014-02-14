//
//  MscLocalException.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.23..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscErrorCodes.h"

@interface MscLocalException : NSException

@property(readonly) NSString* errorDomain;
@property(readonly) NSUInteger errorCode;
@property(readonly) NSDictionary* errorUserInfo;

-(MscLocalException*) init __attribute__((unavailable("please, use initWithErrorCode for initialization")));
-(id)initWithErrorCode:(NSUInteger)_errorCode errorUserInfo:(NSDictionary*)_errorUserInfo;

@end
