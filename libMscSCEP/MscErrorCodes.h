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
#define FailedToReadPKCS12File                      1013
#define FailedToWritePKCS12File                     1014
#define FailedToParsePKCS12File                     1015

#define FailedToConvertCertificateSubject           1016
#define FailedToConvertSerialNumber                 1017

#define FailedToDownloadCACertificate               1018
#define FailedToEnrolCertificate                    1019
#define FailedToDownloadCertificateRevocationList   1020
#define FailedToDownloadCertificate                 1021

#define FailedToEncodeSCEPMessage                   1022
#define FailedToDecodeSCEPMessage                   1023

#define FailedToConvertASN1_TIME                    1024

@end