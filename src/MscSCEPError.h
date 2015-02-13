//
//  MscSCEPError.h
//  MscSCEP
//
//  Created by Microsec on 2014.08.08..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>

#define FailedToDownloadCACertificate               1101
#define FailedToEnrollCertificate                   1102
#define FailedToDownloadCertificateRevocationList   1103
#define FailedToDownloadCertificate                 1104
#define FailedToEncodeSCEPMessage                   1105
#define FailedToDecodeSCEPMessage                   1106
#define FailedToConnectToHost                       1107

@interface MscSCEPError : NSError

+(id)errorWithCode:(NSInteger)code;

@end
