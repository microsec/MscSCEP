//
//  NSString+MscRandomExtension.m
//  MscSCEP
//
//  Created by Microsec on 2014.10.02..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "NSString+MscRandomExtension.h"

@implementation NSString (MscRandomExtension)

+(NSString*)randomAlphanumericStringWithLength:(NSInteger)length
{
    NSString *letters = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *randomString = [NSMutableString stringWithCapacity:length];
    
    for (int i = 0; i < length; i++) {
        [randomString appendFormat:@"%C", [letters characterAtIndex:arc4random_uniform((u_int32_t)[letters length])]];
    }
    
    return randomString;
}

@end
