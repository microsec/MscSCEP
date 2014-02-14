//
//  NSString+MscExtensions.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.20..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (MscExtensions)

-(BOOL)isEmpty;
-(NSString *)urlencode;
+(NSString *)randomAlphanumericStringWithLength:(NSInteger)length;
-(const char*)ASCIIString;

@end
