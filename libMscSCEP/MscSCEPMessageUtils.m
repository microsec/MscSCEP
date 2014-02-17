//
//  MscSCEPMessageUtils.m
//  MscSCEP
//
//  Created by Microsec on 2014.02.04..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEPMessageUtils.h"

#import "MscRSAKeyRSA.h"
#import "MscCertificateSigningRequestX509_REQ.h"
#import "MscCertificateX509.h"
#import "MscCertificateRevocationListX509_CRL.h"
#import "MscLocalException.h"
#import "MscCertificateUtils.h"
#import "MscSCEPResponsePrivate.h"
#import "MscOpenSSLExtension.h"
#import "NSString+MscExtensions.h"

#import <openssl/x509.h>

@implementation MscSCEPMessageUtils

static int nid_messageType;
static int nid_pkiStatus;
static int nid_failInfo;
static int nid_senderNonce;
static int nid_recipientNonce;
static int nid_transId;
static int nid_extensionReq;

+ (void)initialize {
    
    nid_messageType = OBJ_create("2.16.840.1.113733.1.9.2", "messageType",
                                 "messageType");
    nid_pkiStatus = OBJ_create("2.16.840.1.113733.1.9.3", "pkiStatus",
                               "pkiStatus");
    nid_failInfo = OBJ_create("2.16.840.1.113733.1.9.4", "failInfo",
                              "failInfo");
    nid_senderNonce = OBJ_create("2.16.840.1.113733.1.9.5", "senderNonce",
                                 "senderNonce");
    nid_recipientNonce = OBJ_create("2.16.840.1.113733.1.9.6",
                                    "recipientNonce", "recipientNonce");
    nid_transId = OBJ_create("2.16.840.1.113733.1.9.7", "transId",
                             "transId");
    nid_extensionReq = OBJ_create("2.16.840.1.113733.1.9.8",
                                  "extensionReq", "extensionReq");
}

+(NSString*)encodeSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(NSError**)error {
    
    unsigned char *requestData = NULL;
    BIO	*requestBIO = NULL;
    STACK_OF(X509) *recipients = NULL;
    BIO	*beEncrypted = NULL;
    PKCS7 *encryptedPKCS7 = NULL;
    unsigned char* encryptedPKCS7Data = NULL;
    BIO	*encryptedPKCS7BIO = NULL;
    PKCS7 *signedPKCS7 = NULL;
    PKCS7_SIGNER_INFO *signerInfo = NULL;
    STACK_OF(X509_ATTRIBUTE) *signedPKCS7attributes = NULL;
    BIO	*signedPKCS7BIO = NULL;
    BIO *memoryBIO = NULL;
    BIO *base64BIO = NULL;
    BIO *base64EncodedPKCS7BIO = NULL;
    
    PKCS7_ISSUER_AND_SUBJECT *issuerAndSubject = NULL;
    PKCS7_ISSUER_AND_SERIAL *issuerAndSerial = NULL;
    
    @try {
        
        int returnCode;
        
        long requestLength;
        
        if (messageType == SCEPMessage_PKCSReq) {
        
            requestLength = i2d_X509_REQ(transaction.certificateSigningRequest._request, &requestData);
            if (requestLength < 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function i2d_X509_REQ returned with: %ld", requestLength]}];
            }
        }
        else if (messageType == SCEPMessage_GetCertInitial) {
            
            issuerAndSubject = PKCS7_ISSUER_AND_SUBJECT_new();
            if (!issuerAndSubject) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: issuerAndSubject"}];
            }
            
            NSError *error;
            issuerAndSubject->issuer = [MscCertificateUtils convertMscCertificateSubjectToX509_NAME:transaction.issuerAndSubject.issuer error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            issuerAndSubject->subject = [MscCertificateUtils convertMscCertificateSubjectToX509_NAME:transaction.issuerAndSubject.subject error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            requestLength = i2d_PKCS7_ISSUER_AND_SUBJECT(issuerAndSubject, &requestData);
            if (requestLength < 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function i2d_PKCS7_ISSUER_AND_SUBJECT returned with: %ld", requestLength]}];
            }
        }
        else if (messageType == SCEPMessage_GetCRL || messageType == SCEPMessage_GetCert) {
            
            issuerAndSerial = PKCS7_ISSUER_AND_SERIAL_new();
            if (!issuerAndSerial) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: issuerAndSerial"}];
            }
            
            NSError *error;
            issuerAndSerial->issuer = [MscCertificateUtils convertMscCertificateSubjectToX509_NAME:transaction.issuerAndSerial.issuer error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            issuerAndSerial->serial = [MscCertificateUtils convertNSStringToASN1_INTEGER:transaction.issuerAndSerial.serial error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            requestLength = i2d_PKCS7_ISSUER_AND_SERIAL(issuerAndSerial, &requestData);
            if (requestLength < 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function i2d_PKCS7_ISSUER_AND_SERIAL returned with: %ld", requestLength]}];
            }
        }
        
        recipients = sk_X509_new_null();
        if (!recipients) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: recipients"}];
        }
        
        sk_X509_push(recipients, transaction.caCertificate._x509);
        
        beEncrypted = BIO_new_mem_buf(requestData, (int)requestLength);
        if (!beEncrypted) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: beEncrypted"}];
        }
        
        encryptedPKCS7 = PKCS7_encrypt(recipients, beEncrypted, EVP_des_ede3_cbc(), PKCS7_BINARY);
        if (!encryptedPKCS7) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: PKCS7_encrypt"}];
        }
        
        long encryptedPKCS7Length = i2d_PKCS7(encryptedPKCS7, &encryptedPKCS7Data);
        if (encryptedPKCS7Length < 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function i2d_PKCS7 returned with: %ld", encryptedPKCS7Length]}];
        }
        
        signedPKCS7 = PKCS7_new();
        if (!signedPKCS7) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: signedPKCS7"}];
        }
        
        returnCode = PKCS7_set_type(signedPKCS7, NID_pkcs7_signed);
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function PKCS7_set_type returned with: %d", returnCode ] }];
        }
        
        returnCode = PKCS7_add_certificate(signedPKCS7, transaction.signerCertificate._x509);
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function PKCS7_add_certificate returned with: %d", returnCode ] }];
        }
        
        signerInfo = PKCS7_add_signature(signedPKCS7, transaction.signerCertificate._x509, transaction.signerKey._evpkey, EVP_get_digestbyobj(transaction.signerCertificate._x509->sig_alg->algorithm));
        if (!signerInfo) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: PKCS7_add_signature"}];
        }
        
        
        signedPKCS7attributes = sk_X509_ATTRIBUTE_new_null();
        if (!signedPKCS7attributes) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: signedPKCS7"}];
        }
        
        NSError* error;
        
        [MscSCEPMessageUtils setAttribute:signedPKCS7attributes nid:nid_transId type:V_ASN1_PRINTABLESTRING value:transaction.transactionID error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        [MscSCEPMessageUtils setAttribute:signedPKCS7attributes nid:nid_messageType type:V_ASN1_PRINTABLESTRING value: [NSString stringWithFormat:@"%lu",(unsigned long)messageType] error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        [MscSCEPMessageUtils setAttribute:signedPKCS7attributes nid:nid_senderNonce type:V_ASN1_OCTET_STRING value: transaction.senderNonce error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        returnCode = PKCS7_set_signed_attributes(signerInfo, signedPKCS7attributes);
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function PKCS7_set_signed_attributes returned with: %d", returnCode ] }];
        }
        
        returnCode = PKCS7_add_signed_attribute(signerInfo, NID_pkcs9_contentType,
                                                V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function PKCS7_add_signed_attribute returned with: %d", returnCode ] }];
        }
        
        returnCode = PKCS7_content_new(signedPKCS7, NID_pkcs7_data);
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function PKCS7_content_new returned with: %d", returnCode ] }];
        }
        
        signedPKCS7BIO = PKCS7_dataInit(signedPKCS7, NULL);
        if (!signedPKCS7BIO) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: PKCS7_add_signature"}];
        }
        
        returnCode = BIO_write(signedPKCS7BIO, encryptedPKCS7Data, (int)encryptedPKCS7Length);
        if (returnCode != encryptedPKCS7Length) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: BIO_write"}];
        }
        
        returnCode = PKCS7_dataFinal(signedPKCS7, signedPKCS7BIO);
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function PKCS7_dataFinal returned with: %d", returnCode ] }];
        }
        
        memoryBIO = BIO_new(BIO_s_mem());
        if (!memoryBIO) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: memoryBIO"}];
        }
        
        base64BIO = BIO_new(BIO_f_base64());
        if (!base64BIO) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: base64BIO"}];
        }
        
        base64EncodedPKCS7BIO = BIO_push(base64BIO, memoryBIO);
        if (!base64EncodedPKCS7BIO) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: BIO_push"}];
        }
        
        returnCode = i2d_PKCS7_bio(base64EncodedPKCS7BIO, signedPKCS7);
        if (!returnCode) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function i2d_PKCS7_bio returned with: %d", returnCode ] }];
        }
        
        BIO_flush(base64EncodedPKCS7BIO);
        BIO_set_flags(memoryBIO, BIO_FLAGS_MEM_RDONLY);
        
        char* scepRequestData;
        long scepRequestLength = BIO_get_mem_data(memoryBIO, &scepRequestData);
        
        return [[NSString alloc] initWithBytes:scepRequestData length:scepRequestLength encoding:NSASCIIStringEncoding];

        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
    }
    @finally {
        
        PKCS7_ISSUER_AND_SERIAL_free(issuerAndSerial);
        PKCS7_ISSUER_AND_SUBJECT_free(issuerAndSubject);
        BIO_free_all(base64EncodedPKCS7BIO);
        BIO_free(signedPKCS7BIO);
        PKCS7_free(signedPKCS7);
        sk_X509_ATTRIBUTE_pop_free(signedPKCS7attributes, X509_ATTRIBUTE_free);
        BIO_free(encryptedPKCS7BIO);
        PKCS7_free(encryptedPKCS7);
        OPENSSL_free(encryptedPKCS7Data);
        BIO_free(beEncrypted);
        sk_X509_free(recipients);
        BIO_free(requestBIO);
        OPENSSL_free(requestData);
    }
}

+(MscSCEPResponse*)decodeSCEPMessageWithTransaction:(MscSCEPTransaction*)transaction responseData:(NSData*)responseData requestMessageType:(SCEPMessage)requestMessageType error:(NSError**)error {
    
    PKCS7 *responsePKCS7 = NULL;
    BIO *signedPKCS7BIO = NULL;
    BIO *envelopedPKCS7BIO = NULL;
    PKCS7 *envelopedPKCS7 = NULL;
    BIO *decryptedPKCS7BIO = NULL;
    PKCS7 *decryptedPKCS7 = NULL;
    
    @try {
        
        int returnCode;
        
        const unsigned char* responsePtr = [responseData bytes];
        
        responsePKCS7 = d2i_PKCS7(NULL, &responsePtr, [responseData length]);
        if (!responsePKCS7) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to decode SCEP message, response is not a valid PKCS7 structure. Response in ASCII encoding: %@", [[NSString alloc] initWithData:responseData encoding:NSASCIIStringEncoding]]}];
        }
        
        
        if (!PKCS7_type_is_signed(responsePKCS7)) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, response PKCS7 type is not signed"}];
        }
        
        signedPKCS7BIO = PKCS7_dataInit(responsePKCS7, NULL);
        if (!signedPKCS7BIO) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: signedPKCS7BIO"}];
        }
        
        envelopedPKCS7BIO = BIO_new(BIO_s_mem());
        if (!envelopedPKCS7BIO) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: envelopedPKCS7BIO"}];
        }
        
        //copy signedPKCS7BIO to envelopedPKCS7BIO
        int readBytes;
        unsigned char buffer[1024];
        int signedPKCS7BIOLength = 0;
        for (;;) {
            readBytes = BIO_read(signedPKCS7BIO, buffer, sizeof(buffer));
            signedPKCS7BIOLength += readBytes;
            if (readBytes <= 0) break;
            BIO_write(envelopedPKCS7BIO, buffer, readBytes);
        }
        BIO_flush(envelopedPKCS7BIO);
        
        STACK_OF(PKCS7_SIGNER_INFO) *signerInfoStack = PKCS7_get_signer_info(responsePKCS7);
        if (!signerInfoStack) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, function: PKCS7_get_signer_info"}];
        }
        
        PKCS7_SIGNER_INFO *signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfoStack, 0);
        if (!signerInfo) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, function: sk_PKCS7_SIGNER_INFO_value"}];
        }

        returnCode = PKCS7_signatureVerify(signedPKCS7BIO, responsePKCS7, signerInfo, transaction.caCertificate._x509);
        if (returnCode <= 0) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to decode SCEP message, function PKCS7_signatureVerify returned with: %d", returnCode ] }];
        }
        
        STACK_OF(X509_ATTRIBUTE) *x509Attributes = PKCS7_get_signed_attributes(signerInfo);
        if (!x509Attributes) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, function: PKCS7_get_signed_attributes"}];
        }
        
        NSError* error;
        NSString* reponseTransactionId = [MscSCEPMessageUtils getSignedAttribute:x509Attributes nid:nid_transId type:V_ASN1_PRINTABLESTRING error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        if (![reponseTransactionId isEqualToString:transaction.transactionID]) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, response transactionId is different from request transactionId"}];
        }
        
        NSString* messageType = [MscSCEPMessageUtils getSignedAttribute:x509Attributes nid:nid_messageType type:V_ASN1_PRINTABLESTRING error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        MscSCEPResponse* response = [[MscSCEPResponse alloc] init];
        response.messageType = [messageType integerValue];
        
        NSString* recipientNonce = [MscSCEPMessageUtils getSignedAttribute:x509Attributes nid:nid_recipientNonce type:V_ASN1_OCTET_STRING error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        if (![transaction.senderNonce isEqualToString:recipientNonce]) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, recipientNonce is different from senderNonce"}];
        }
        
        NSString* pkiStatus = [MscSCEPMessageUtils getSignedAttribute:x509Attributes nid:nid_pkiStatus type:V_ASN1_PRINTABLESTRING error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        response.pkiStatus = [pkiStatus integerValue];
        
        if (response.pkiStatus == SCEPPKIStatus_FAILURE) {
            NSString* failInfo = [MscSCEPMessageUtils getSignedAttribute:x509Attributes nid:nid_failInfo type:V_ASN1_PRINTABLESTRING error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            response.failInfo = [failInfo integerValue];
        }
        else if (response.pkiStatus == SCEPPKIStatus_SUCCESS && response.messageType == SCEPMessage_CertRep) {
            
            response.failInfo = SCEPFailInfo_NoError;
            
            envelopedPKCS7 = d2i_PKCS7_bio(envelopedPKCS7BIO, NULL);
            if (!envelopedPKCS7) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, enveloped object is not a valid PKCS7 structure"}];
            }
            
            decryptedPKCS7BIO = BIO_new(BIO_s_mem());
            if (!decryptedPKCS7BIO) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: decryptedPKCS7BIO"}];
            }
            
            returnCode = PKCS7_decrypt(envelopedPKCS7, transaction.signerKey._evpkey, transaction.signerCertificate._x509, decryptedPKCS7BIO, 0);
            if (returnCode == 0) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to decode SCEP message, function PKCS7_decrypt returned with: %d", returnCode ] }];
            }
            BIO_flush(decryptedPKCS7BIO);
            
            char* decryptedPKCS7Data;
            long decryptedPKCS7Length = BIO_get_mem_data(decryptedPKCS7BIO, &decryptedPKCS7Data);
            if (decryptedPKCS7Length < 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to decode SCEP message, function BIO_get_mem_data returned with: %ld", decryptedPKCS7Length ] }];
            }
            BIO_set_flags(decryptedPKCS7BIO, BIO_FLAGS_MEM_RDONLY);
            
            decryptedPKCS7 = d2i_PKCS7_bio(decryptedPKCS7BIO, NULL);
            if (!decryptedPKCS7) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: decryptedPKCS7"}];
            }
            
            
            if (requestMessageType == SCEPMessage_PKCSReq || requestMessageType == SCEPMessage_GetCertInitial || requestMessageType == SCEPMessage_GetCert) {
                STACK_OF(X509) *enrolledCertificates = decryptedPKCS7->d.sign->cert;
                if (!enrolledCertificates) {
                    @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, decryptedPKCS7->d.sign->cert stack is empty"}];
                }
                
                NSMutableArray* certificates = [NSMutableArray arrayWithCapacity:sk_X509_num(enrolledCertificates)];
                for (int i = 0; i < sk_X509_num(enrolledCertificates); i++) {
                    X509* copyOfEnrolledCert = X509_dup(sk_X509_value(enrolledCertificates, i));
                    [certificates addObject:[[MscCertificate alloc] initWithX509:copyOfEnrolledCert]];
                }
                response.certificates = certificates;
            }
            else if(requestMessageType == SCEPMessage_GetCRL) {
                
                STACK_OF(X509_CRL) *crls = decryptedPKCS7->d.sign->crl;
                if (!crls) {
                    @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, decryptedPKCS7->d.sign->crl stack is empty"}];
                }
                NSMutableArray* crlArray = [NSMutableArray arrayWithCapacity:sk_X509_CRL_num(crls)];
                for (int i = 0; i < sk_X509_CRL_num(crls); i++) {
                    [crlArray addObject:[[MscCertificateRevocationList alloc] initWithX509_CRL:X509_CRL_dup(sk_X509_CRL_value(crls, i))]];
                }
                response.certificateRevocationLists = crlArray;
            }
        }
        else if (response.pkiStatus == SCEPPKIStatus_PENDING) {
            
            response.failInfo = SCEPFailInfo_NoError;
            
            X509_NAME* issuer = X509_get_issuer_name(transaction.signerCertificate._x509);
            if(!issuer) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, function: X509_get_issuer_name"}];
            }
           
            X509_NAME* subject = X509_get_subject_name(transaction.signerCertificate._x509);
            if(!subject) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, function: X509_get_subject_name"}];
            }
            
            NSError *error;
            transaction.issuerAndSubject = [[MscIssuerAndSubject alloc] init];
            transaction.issuerAndSubject.issuer = [MscCertificateUtils convertX509_NAMEToMscCertificateSubject:issuer error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
            
            transaction.issuerAndSubject.subject = [MscCertificateUtils convertX509_NAMEToMscCertificateSubject:subject error:&error];
            if (nil != error) {
                @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
            }
        }
        
        response.transaction = transaction;
        
        return response;
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
    @finally {

        if (decryptedPKCS7) PKCS7_free(decryptedPKCS7);
        if (decryptedPKCS7BIO) BIO_free(decryptedPKCS7BIO);
        if (envelopedPKCS7) PKCS7_free(envelopedPKCS7);
        
        BIO_free(envelopedPKCS7BIO);
        BIO_free(signedPKCS7BIO);
        PKCS7_free(responsePKCS7);
    }
}

+(void)setAttribute:(STACK_OF(X509_ATTRIBUTE)*)attributes nid:(NSInteger)nid type:(NSInteger)type value:(NSString*)value error:(NSError**)error {
    
    ASN1_STRING *asn1String = NULL;
    X509_ATTRIBUTE *x509Attribute = NULL;
    
    @try {
        
        int returnCode;
        
        ASN1_STRING *asn1String = ASN1_STRING_new();
        if (!asn1String) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: asn1String"}];
        }
        
        if ((returnCode = ASN1_STRING_set(asn1String, [value ASCIIString], (int)[value length])) <= 0) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to encode SCEP message, function ASN1_STRING_set returned with: %d", returnCode ] }];
        }
        
        X509_ATTRIBUTE *x509Attribute = X509_ATTRIBUTE_create((int)nid, (int)type,                                                asn1String);
        if (!x509Attribute) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: x509Attribute"}];
        }
        
        sk_X509_ATTRIBUTE_push(attributes, x509Attribute);
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        ASN1_STRING_free(asn1String);
        X509_ATTRIBUTE_free(x509Attribute);
    }
}

+(NSString*)getSignedAttribute:(STACK_OF(X509_ATTRIBUTE)*)attributes nid:(NSInteger)nid type:(NSInteger)type error:(NSError**)error {
    
    ASN1_TYPE *asn1Type = NULL;
    
    @try {
        
        NSError* _error;
        asn1Type = [MscSCEPMessageUtils getAttribute:attributes nid:nid error:&_error];
        if (nil != _error) {
            @throw [[MscLocalException alloc] initWithErrorCode:_error.code errorUserInfo:_error.userInfo];
        }
        if (ASN1_TYPE_get(asn1Type) != type) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: ASN1_TYPE_get"}];
        }
        
        return [[NSString alloc] initWithBytes:ASN1_STRING_data(asn1Type->value.asn1_string) length:asn1Type->value.asn1_string->length encoding:NSASCIIStringEncoding];
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        ASN1_TYPE_free(asn1Type);
        return nil;
    }
}

+(ASN1_TYPE*)getAttribute:(STACK_OF(X509_ATTRIBUTE)*)attributes nid:(NSInteger)nid error:(NSError**)error {
    
    @try {
        
        ASN1_OBJECT	*asn1Object = OBJ_nid2obj((int)nid);
        if (!asn1Object) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToEncodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to encode SCEP message, function: OBJ_nid2obj"}];
        }
        
        ASN1_TYPE *asn1Type = NULL;
        for (int i = 0; i < sk_X509_ATTRIBUTE_num(attributes); i++) {
            X509_ATTRIBUTE *x509Attribute = x509Attribute = sk_X509_ATTRIBUTE_value(attributes, i);
            if (OBJ_cmp(x509Attribute->object, asn1Object) == 0) {
                if ((x509Attribute->value.set) && (sk_ASN1_TYPE_num(x509Attribute->value.set) != 0)) {
                    asn1Type = sk_ASN1_TYPE_value(x509Attribute->value.set, 0);
                    break;
                }
            }
        }
        return asn1Type;
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

+(MscSCEPResponse*)createAndSendSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        NSString* request = [MscSCEPMessageUtils encodeSCEPMessageWithMessageType:messageType transaction:transaction error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        NSURL* url = [NSURL URLWithString: [NSString stringWithFormat:@"%@?operation=PKIOperation&message=%@", [transaction.scepServerURL absoluteString], [request urlencode]]];
        NSURLRequest* urlRequest = [NSURLRequest requestWithURL:url];
        
        NSData *payLoad;
        NSURLResponse* response;
        
        payLoad = [NSURLConnection sendSynchronousRequest:urlRequest returningResponse:&response error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        if ([payLoad length] == 0) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to decode SCEP message, response of SCEP server is empty"}];
        }
        
        if (![response.MIMEType isEqualToString:MIME_PKI]) {
            NSLog(@"%@", response.MIMEType);
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToDecodeSCEPMessage errorUserInfo: @{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to decode SCEP message, mime type of response is: %@", response.MIMEType]}];
        }
        
        MscSCEPResponse* scepResponse = [MscSCEPMessageUtils decodeSCEPMessageWithTransaction:transaction responseData:payLoad requestMessageType:messageType error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        return scepResponse;
        
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

@end
