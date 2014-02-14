//
//  MscRSAKey.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, KeySize) {
    KeySize_2048 = 2048,
    KeySize_4096 = 4096
};

@interface MscRSAKey : NSObject

-(id)init __attribute__((unavailable("please, use initWithKeySize or initWithContentsOfFile for initialization")));
-(id)initWithKeySize:(KeySize)keySize error:(NSError**)error;
-(id)initWithContentsOfFile:(NSString*)path error:(NSError**)error;
-(void)saveToPath:(NSString *)path error:(NSError **)error;

@end
