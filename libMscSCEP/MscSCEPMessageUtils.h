//
//  MscSCEPMessageUtils.h
//  MscSCEP
//
//  Created by Microsec on 2014.02.04..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MscSCEPResponse.h"
#import "MscSCEPTransaction.h"

@interface MscSCEPMessageUtils : NSObject

+(NSString*)encodeSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(NSError**)error;
+(MscSCEPResponse*)decodeSCEPMessageWithTransaction:(MscSCEPTransaction*)transaction responseData:(NSData*)responseData requestMessageType:(SCEPMessage)requestMessageType error:(NSError**)error;
+(MscSCEPResponse*) createAndSendSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(NSError**)error;

@end
