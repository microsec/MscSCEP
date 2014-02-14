//
//  MscErrorCodes.h
//  MscSCEP
//
//  Created by Microsec on 2014.01.20..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MscErrorCodes : NSObject

#define FailedToAllocateMemory                      1000
#define IOError                                     1001

#define FailedToGenerateKey                         1002
#define FailedToReadKeyFile                         1003
#define FailedToWriteKeyFile                        1004
#define FailedToGenerateRequest                     1005
#define FailedToReadRequest                         1006
#define FailedToWriteRequest                        1007
#define FailedToGenerateCertificate                 1008
#define FailedToReadCertificate                     1009
#define FailedToWriteCertificate                    1010
#define FailedToReadCertificateRevocationList       1011
#define FailedToWriteCertificateRevocationList      1012

#define FailedToConvertCertificateSubject           1013
#define FailedToConvertSerialNumber                 1014

#define FailedToDownloadCACertificate               1015
#define FailedToEnrolCertificate                    1016
#define FailedToDownloadCertificateRevocationList   1017
#define FailedToDownloadCertificate                 1018

#define FailedToEncodeSCEPMessage                   1019
#define FailedToDecodeSCEPMessage                   1020



@end