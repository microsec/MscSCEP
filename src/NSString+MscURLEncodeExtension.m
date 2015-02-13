//
//  NSString+MscURLEncodeExtension.m
//  MscSCEP
//
//  Created by Microsec on 2014.10.02..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "NSString+MscURLEncodeExtension.h"

@implementation NSString (MscURLEncodeExtension)

-(NSString *)urlencode {
    NSMutableString *output = [NSMutableString string];
    const unsigned char *source = (const unsigned char *)[self cStringUsingEncoding:[NSString defaultCStringEncoding]];
    unsigned long sourceLen = strlen((const char *)source);
    for (int i = 0; i < sourceLen; ++i) {
        const unsigned char thisChar = source[i];
        if (thisChar == ' '){
            [output appendString:@"+"];
        } else if (thisChar == '.' || thisChar == '-' || thisChar == '_' || thisChar == '~' ||
                   (thisChar >= 'a' && thisChar <= 'z') ||
                   (thisChar >= 'A' && thisChar <= 'Z') ||
                   (thisChar >= '0' && thisChar <= '9')) {
            [output appendFormat:@"%c", thisChar];
        } else {
            [output appendFormat:@"%%%02X", thisChar];
        }
    }
    return output;
}

@end
