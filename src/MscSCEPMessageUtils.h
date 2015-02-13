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
#import "MscSCEP.h"
#import "MscHTTPSURLConnection/MscHTTPSValidatorDelegate.h"

@interface MscSCEPMessageUtils : NSObject<NSURLConnectionDelegate>

-(NSString*)encodeSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(MscSCEPError**)error;
-(MscSCEPResponse*)decodeSCEPMessageWithTransaction:(MscSCEPTransaction*)transaction responseData:(NSData*)responseData requestMessageType:(SCEPMessage)requestMessageType error:(MscSCEPError**)error;
//-(MscSCEPResponse*)createAndSendSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction validatorDelegate:(id<MscHTTPSValidatorDelegate>)validatorDelegate error:(MscSCEPError**)error;
-(MscSCEPResponse*)createAndSendSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(MscSCEPError**)error;

@end
