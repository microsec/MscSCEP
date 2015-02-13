//
//  MscSCEPMessageUtils.m
//  MscSCEP
//
//  Created by Microsec on 2014.02.04..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscSCEPMessageUtils.h"
#import "MscSCEPLocalException.h"
#import "MscSCEPResponsePrivate.h"
#import "NSString+MscRandomExtension.h"
#import "NSString+MscURLEncodeExtension.h"

#import "MscHTTPSURLConnection/MscHTTPSURLConnection.h"
#import "MscHTTPSURLConnection/MscHTTPSValidatorDelegate.h"

#import "MscX509Common/MscRSAKey_OpenSSL_RSA.h"
#import "MscX509Common/MscCertificateSigningRequest_OpenSSL_X509_REQ.h"
#import "MscX509Common/MscCertificate_OpenSSL_X509.h"
#import "MscX509Common/MscCertificateRevocationList_OpenSSL_X509_CRL.h"
#import "MscX509Common/MscPKCS12_OpenSSL_PKCS12.h"
#import "MscX509Common/MscCertificateUtils.h"
#import "MscX509Common/MscOpenSSLExtension.h"
#import "MscX509Common/NSString+MscASCIIExtension.h"

#import <openssl/x509.h>

@implementation MscSCEPMessageUtils {
    
    NSURLConnection* _urlConnection;
    NSURLResponse* _urlResponse;
    NSError* _httpConnectionError;
    NSMutableData* _payLoad;
    MscSCEPTransaction* _transaction;
}

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

-(NSString*)encodeSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(MscSCEPError**)error {
    
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
        NSError *localError;
        
        long requestLength;
        
        if (messageType == SCEPMessage_PKCSReq) {
        
            requestLength = i2d_X509_REQ(transaction.certificateSigningRequest._request, &requestData);
            if (requestLength < 1) {
                NSLog(@"Failed to encode SCEP message, function i2d_X509_REQ returned with: %ld", requestLength);
                @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
            }
        }
        else if (messageType == SCEPMessage_GetCertInitial) {
            
            issuerAndSubject = PKCS7_ISSUER_AND_SUBJECT_new();
            if (!issuerAndSubject) {
                NSLog(@"Failed to allocate memory for variable: issuerAndSubject");
                @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
            }
            
            issuerAndSubject->issuer = [MscCertificateUtils convertMscX509NameToX509_NAME:transaction.issuerAndSubject.issuer];
            issuerAndSubject->subject = [MscCertificateUtils convertMscX509NameToX509_NAME:transaction.issuerAndSubject.subject];
            
            requestLength = i2d_PKCS7_ISSUER_AND_SUBJECT(issuerAndSubject, &requestData);
            if (requestLength < 1) {
                NSLog(@"Failed to encode SCEP message, function i2d_PKCS7_ISSUER_AND_SUBJECT returned with: %ld", requestLength);
                @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
            }
        }
        else if (messageType == SCEPMessage_GetCRL || messageType == SCEPMessage_GetCert) {
            
            issuerAndSerial = PKCS7_ISSUER_AND_SERIAL_new();
            if (!issuerAndSerial) {
                NSLog(@"Failed to allocate memory for variable: issuerAndSerial");
                @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
            }
            
            issuerAndSerial->issuer = [MscCertificateUtils convertMscX509NameToX509_NAME:transaction.issuerAndSerial.issuer];
            issuerAndSerial->serial = [MscCertificateUtils convertNSStringToASN1_INTEGER:transaction.issuerAndSerial.serial];
            
            requestLength = i2d_PKCS7_ISSUER_AND_SERIAL(issuerAndSerial, &requestData);
            if (requestLength < 1) {
                NSLog(@"Failed to encode SCEP message, function i2d_PKCS7_ISSUER_AND_SERIAL returned with: %ld", requestLength);
                @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
            }
        }
        
        recipients = sk_X509_new_null();
        if (!recipients) {
            NSLog(@"Failed to allocate memory for variable: recipients");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        sk_X509_push(recipients, transaction.caCertificate._x509);
        
        beEncrypted = BIO_new_mem_buf(requestData, (int)requestLength);
        if (!beEncrypted) {
            NSLog(@"Failed to allocate memory for variable: beEncrypted");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        encryptedPKCS7 = PKCS7_encrypt(recipients, beEncrypted, EVP_des_ede3_cbc(), PKCS7_BINARY);
        if (!encryptedPKCS7) {
            NSLog(@"Failed to encode SCEP message, function: PKCS7_encrypt");
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        long encryptedPKCS7Length = i2d_PKCS7(encryptedPKCS7, &encryptedPKCS7Data);
        if (encryptedPKCS7Length < 1) {
            NSLog(@"Failed to encode SCEP message, function i2d_PKCS7 returned with: %ld", encryptedPKCS7Length);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        signedPKCS7 = PKCS7_new();
        if (!signedPKCS7) {
            NSLog(@"Failed to allocate memory for variable: signedPKCS7");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        returnCode = PKCS7_set_type(signedPKCS7, NID_pkcs7_signed);
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function PKCS7_set_type returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        returnCode = PKCS7_add_certificate(signedPKCS7, transaction.signerCertificate._x509);
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function PKCS7_add_certificate returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        signerInfo = PKCS7_add_signature(signedPKCS7, transaction.signerCertificate._x509, transaction.signerKey._evp_pkey, EVP_get_digestbynid(OBJ_obj2nid(transaction.signerCertificate._x509->sig_alg->algorithm)));
        if (!signerInfo) {
            NSLog(@"Failed to encode SCEP message, function: PKCS7_add_signature");
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        
        signedPKCS7attributes = sk_X509_ATTRIBUTE_new_null();
        if (!signedPKCS7attributes) {
            NSLog(@"Failed to allocate memory for variable: signedPKCS7");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        [self setAttribute:signedPKCS7attributes nid:nid_transId type:V_ASN1_PRINTABLESTRING value:transaction.transactionID error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        [self setAttribute:signedPKCS7attributes nid:nid_messageType type:V_ASN1_PRINTABLESTRING value: [NSString stringWithFormat:@"%lu",(unsigned long)messageType] error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        [self setAttribute:signedPKCS7attributes nid:nid_senderNonce type:V_ASN1_OCTET_STRING value: transaction.senderNonce error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        returnCode = PKCS7_set_signed_attributes(signerInfo, signedPKCS7attributes);
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function PKCS7_set_signed_attributes returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        returnCode = PKCS7_add_signed_attribute(signerInfo, NID_pkcs9_contentType,
                                                V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function PKCS7_add_signed_attribute returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        returnCode = PKCS7_content_new(signedPKCS7, NID_pkcs7_data);
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function PKCS7_content_new returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        signedPKCS7BIO = PKCS7_dataInit(signedPKCS7, NULL);
        if (!signedPKCS7BIO) {
            NSLog(@"Failed to encode SCEP message, function: PKCS7_dataInit");
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        returnCode = BIO_write(signedPKCS7BIO, encryptedPKCS7Data, (int)encryptedPKCS7Length);
        if (returnCode != encryptedPKCS7Length) {
            NSLog(@"Failed to encode SCEP message, function: BIO_write");
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        returnCode = PKCS7_dataFinal(signedPKCS7, signedPKCS7BIO);
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function PKCS7_dataFinal returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        memoryBIO = BIO_new(BIO_s_mem());
        if (!memoryBIO) {
            NSLog(@"Failed to allocate memory for variable: memoryBIO");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        base64BIO = BIO_new(BIO_f_base64());
        if (!base64BIO) {
            NSLog(@"Failed to allocate memory for variable: base64BIO");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        base64EncodedPKCS7BIO = BIO_push(base64BIO, memoryBIO);
        if (!base64EncodedPKCS7BIO) {
            NSLog(@"Failed to encode SCEP message, function: BIO_push");
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        returnCode = i2d_PKCS7_bio(base64EncodedPKCS7BIO, signedPKCS7);
        if (!returnCode) {
            NSLog(@"Failed to encode SCEP message, function i2d_PKCS7_bio returned with: %d", returnCode);
            @throw [MscSCEPError errorWithCode:FailedToEncodeSCEPMessage];
        }
        
        BIO_flush(base64EncodedPKCS7BIO);
        BIO_set_flags(memoryBIO, BIO_FLAGS_MEM_RDONLY);
        
        char* scepRequestData;
        long scepRequestLength = BIO_get_mem_data(memoryBIO, &scepRequestData);
        
        return [[NSString alloc] initWithBytes:scepRequestData length:scepRequestLength encoding:NSASCIIStringEncoding];
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
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

-(MscSCEPResponse*)decodeSCEPMessageWithTransaction:(MscSCEPTransaction*)transaction responseData:(NSData*)responseData requestMessageType:(SCEPMessage)requestMessageType error:(MscSCEPError**)error {
    
    PKCS7 *responsePKCS7 = NULL;
    BIO *signedPKCS7BIO = NULL;
    BIO *envelopedPKCS7BIO = NULL;
    PKCS7 *envelopedPKCS7 = NULL;
    BIO *decryptedPKCS7BIO = NULL;
    PKCS7 *decryptedPKCS7 = NULL;
    
    @try {
        
        int returnCode;
        NSError* localError;
        
        const unsigned char* responsePtr = [responseData bytes];
        
        responsePKCS7 = d2i_PKCS7(NULL, &responsePtr, [responseData length]);
        if (!responsePKCS7) {
            NSLog(@"Failed to decode SCEP message, response is not a valid PKCS7 structure. Response in ASCII encoding: %@", [[NSString alloc] initWithData:responseData encoding:NSASCIIStringEncoding]);
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        
        if (!PKCS7_type_is_signed(responsePKCS7)) {
            NSLog(@"Failed to decode SCEP message, response PKCS7 type is not signed");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        signedPKCS7BIO = PKCS7_dataInit(responsePKCS7, NULL);
        if (!signedPKCS7BIO) {
            NSLog(@"Failed to allocate memory for variable: signedPKCS7BIO");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        envelopedPKCS7BIO = BIO_new(BIO_s_mem());
        if (!envelopedPKCS7BIO) {
            NSLog(@"Failed to allocate memory for variable: envelopedPKCS7BIO");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        //copy signedPKCS7BIO to envelopedPKCS7BIO
        int readBytes;
        unsigned char buffer[1024];
        int signedPKCS7BIOLength = 0;
        for (;;) {
            readBytes = BIO_read(signedPKCS7BIO, buffer, sizeof(buffer));
            if (readBytes <= 0) break;
            signedPKCS7BIOLength += readBytes;
            BIO_write(envelopedPKCS7BIO, buffer, readBytes);
        }
        BIO_flush(envelopedPKCS7BIO);
        
        STACK_OF(PKCS7_SIGNER_INFO) *signerInfoStack = PKCS7_get_signer_info(responsePKCS7);
        if (!signerInfoStack) {
            NSLog(@"Failed to decode SCEP message, function: PKCS7_get_signer_info");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        PKCS7_SIGNER_INFO *signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfoStack, 0);
        if (!signerInfo) {
            NSLog(@"Failed to decode SCEP message, function: sk_PKCS7_SIGNER_INFO_value");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }

        returnCode = PKCS7_signatureVerify(signedPKCS7BIO, responsePKCS7, signerInfo, transaction.caCertificate._x509);
        if (returnCode <= 0) {
            NSLog(@"Failed to decode SCEP message, function PKCS7_signatureVerify returned with: %d", returnCode);
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        STACK_OF(X509_ATTRIBUTE) *x509Attributes = PKCS7_get_signed_attributes(signerInfo);
        if (!x509Attributes) {
            NSLog(@"Failed to decode SCEP message, function: PKCS7_get_signed_attributes");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        NSString* reponseTransactionId = [self getSignedAttribute:x509Attributes nid:nid_transId type:V_ASN1_PRINTABLESTRING error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        if (![reponseTransactionId isEqualToString:transaction.transactionID]) {
            NSLog(@"Failed to decode SCEP message, response transactionId is different from request transactionId");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        NSString* messageType = [self getSignedAttribute:x509Attributes nid:nid_messageType type:V_ASN1_PRINTABLESTRING error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        MscSCEPResponse* response = [[MscSCEPResponse alloc] init];
        response.messageType = [messageType integerValue];
        
        NSString* recipientNonce = [self getSignedAttribute:x509Attributes nid:nid_recipientNonce type:V_ASN1_OCTET_STRING error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        if (![transaction.senderNonce isEqualToString:recipientNonce]) {
            NSLog(@"Failed to decode SCEP message, recipientNonce is different from senderNonce");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
        }
        
        NSString* pkiStatus = [self getSignedAttribute:x509Attributes nid:nid_pkiStatus type:V_ASN1_PRINTABLESTRING error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        response.pkiStatus = [pkiStatus integerValue];
        
        if (response.pkiStatus == SCEPPKIStatus_FAILURE) {
            NSString* failInfo = [self getSignedAttribute:x509Attributes nid:nid_failInfo type:V_ASN1_PRINTABLESTRING error:&localError];
            if (localError) {
                @throw [MscSCEPLocalException exceptionWithCode:localError.code];
            }
            
            response.failInfo = [failInfo integerValue];
        }
        else if (response.pkiStatus == SCEPPKIStatus_SUCCESS && response.messageType == SCEPMessage_CertRep) {
            
            response.failInfo = SCEPFailInfo_NoError;
            
            envelopedPKCS7 = d2i_PKCS7_bio(envelopedPKCS7BIO, NULL);
            if (!envelopedPKCS7) {
                NSLog(@"Failed to decode SCEP message, enveloped object is not a valid PKCS7 structure");
                @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
            }
            
            decryptedPKCS7BIO = BIO_new(BIO_s_mem());
            if (!decryptedPKCS7BIO) {
                NSLog(@"Failed to allocate memory for variable: decryptedPKCS7BIO");
                @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
            }
            
            returnCode = PKCS7_decrypt(envelopedPKCS7, transaction.signerKey._evp_pkey, transaction.signerCertificate._x509, decryptedPKCS7BIO, 0);
            if (returnCode == 0) {
                NSLog(@"Failed to decode SCEP message, function PKCS7_decrypt returned with: %d", returnCode);
                @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
            }
            BIO_flush(decryptedPKCS7BIO);
            
            char* decryptedPKCS7Data;
            long decryptedPKCS7Length = BIO_get_mem_data(decryptedPKCS7BIO, &decryptedPKCS7Data);
            if (decryptedPKCS7Length < 1) {
                NSLog(@"Failed to decode SCEP message, function BIO_get_mem_data returned with: %ld", decryptedPKCS7Length);
                @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
            }
            BIO_set_flags(decryptedPKCS7BIO, BIO_FLAGS_MEM_RDONLY);
            
            decryptedPKCS7 = d2i_PKCS7_bio(decryptedPKCS7BIO, NULL);
            if (!decryptedPKCS7) {
                NSLog(@"Failed to allocate memory for variable: decryptedPKCS7");
                @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
            }
            
            
            if (requestMessageType == SCEPMessage_PKCSReq || requestMessageType == SCEPMessage_GetCertInitial || requestMessageType == SCEPMessage_GetCert) {
                STACK_OF(X509) *enrolledCertificates = decryptedPKCS7->d.sign->cert;
                if (!enrolledCertificates) {
                    NSLog(@"Failed to decode SCEP message, decryptedPKCS7->d.sign->cert stack is empty");
                    @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
                }
                
                NSMutableArray* certificates = [NSMutableArray arrayWithCapacity:sk_X509_num(enrolledCertificates)];
                for (int i = 0; i < sk_X509_num(enrolledCertificates); i++) {
                    X509* copyOfEnrolledCert = X509_dup(sk_X509_value(enrolledCertificates, i));
                    [certificates addObject:[[MscCertificate alloc] initWithX509:copyOfEnrolledCert]];
                }
                response.certificates = certificates;
                
                if (requestMessageType == SCEPMessage_PKCSReq || requestMessageType == SCEPMessage_GetCertInitial) {
                    if (transaction.createPKCS12) {
                        
                        int i;
                        MscCertificate* certificate;
                        for (i = 0; i < [response.certificates count]; i++) {
                            if (X509_check_private_key(((MscCertificate*)[response.certificates objectAtIndex:i])._x509, transaction.signerKey._evp_pkey)) {
                                certificate = [response.certificates objectAtIndex:i];
                                break;
                            }
                        }
                        if (certificate) {
                            response.pkcs12 = [[MscPKCS12 alloc] initWithRSAKey:transaction.signerKey certificate:certificate password:transaction.pkcs12Password error:&localError];
                            if (localError) {
                                @throw [MscSCEPLocalException exceptionWithCode:localError.code];
                            }
                        }
                    }
                }
            }
            else if(requestMessageType == SCEPMessage_GetCRL) {
                
                STACK_OF(X509_CRL) *crls = decryptedPKCS7->d.sign->crl;
                if (!crls) {
                    NSLog(@"Failed to decode SCEP message, decryptedPKCS7->d.sign->crl stack is empty");
                    @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
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
                NSLog(@"Failed to decode SCEP message, function: X509_get_issuer_name");
                @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
            }
           
            X509_NAME* subject = X509_get_subject_name(transaction.signerCertificate._x509);
            if(!subject) {
                NSLog(@"Failed to decode SCEP message, function: X509_get_subject_name");
                @throw [MscSCEPLocalException exceptionWithCode:FailedToDecodeSCEPMessage];
            }
            
            transaction.issuerAndSubject = [[MscIssuerAndSubject alloc] init];
            transaction.issuerAndSubject.issuer = [MscCertificateUtils convertX509_NAMEToMscX509Name:issuer];
            transaction.issuerAndSubject.subject = [MscCertificateUtils convertX509_NAMEToMscX509Name:subject];
        }
        
        response.transaction = transaction;
        
        return response;
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
    }
    @finally {

        PKCS7_free(decryptedPKCS7);
        BIO_free(decryptedPKCS7BIO);
        PKCS7_free(envelopedPKCS7);
        BIO_free(envelopedPKCS7BIO);
        BIO_free(signedPKCS7BIO);
        PKCS7_free(responsePKCS7);
    }
}

-(void)setAttribute:(STACK_OF(X509_ATTRIBUTE)*)attributes nid:(NSInteger)nid type:(NSInteger)type value:(NSString*)value error:(MscSCEPError**)error {
    
    ASN1_STRING *asn1String = NULL;
    X509_ATTRIBUTE *x509Attribute = NULL;
    
    @try {
        
        int returnCode;
        
        ASN1_STRING *asn1String = ASN1_STRING_new();
        if (!asn1String) {
            NSLog(@"Failed to allocate memory for variable: asn1String");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToAllocateMemory];
        }
        
        if ((returnCode = ASN1_STRING_set(asn1String, [value ASCIIString], (int)[value length])) <= 0) {
            NSLog(@"Failed to encode SCEP message, function ASN1_STRING_set returned with: %d", returnCode);
            @throw [MscSCEPLocalException exceptionWithCode:FailedToEncodeSCEPMessage];
        }
        
        X509_ATTRIBUTE *x509Attribute = X509_ATTRIBUTE_create((int)nid, (int)type, asn1String);
        if (!x509Attribute) {
            NSLog(@"Failed to allocate memory for variable: x509Attribute");
            @throw [MscSCEPError errorWithCode:FailedToAllocateMemory];
        }
        
        sk_X509_ATTRIBUTE_push(attributes, x509Attribute);
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        ASN1_STRING_free(asn1String);
        X509_ATTRIBUTE_free(x509Attribute);
    }
}

-(NSString*)getSignedAttribute:(STACK_OF(X509_ATTRIBUTE)*)attributes nid:(NSInteger)nid type:(NSInteger)type error:(MscSCEPError**)error {
    
    ASN1_TYPE *asn1Type = NULL;
    
    @try {
        
        NSError* localError;
        asn1Type = [self getAttribute:attributes nid:nid error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        if (ASN1_TYPE_get(asn1Type) != type) {
            NSLog(@"Failed to encode SCEP message, function: ASN1_TYPE_get");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToEncodeSCEPMessage];
        }
        
        return [[NSString alloc] initWithBytes:ASN1_STRING_data(asn1Type->value.asn1_string) length:asn1Type->value.asn1_string->length encoding:NSASCIIStringEncoding];
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        ASN1_TYPE_free(asn1Type);
        return nil;
    }
}

-(ASN1_TYPE*)getAttribute:(STACK_OF(X509_ATTRIBUTE)*)attributes nid:(NSInteger)nid error:(MscSCEPError**)error {
    
    @try {
        
        ASN1_OBJECT	*asn1Object = OBJ_nid2obj((int)nid);
        if (!asn1Object) {
            NSLog(@"Failed to encode SCEP message, function: OBJ_nid2obj");
            @throw [MscSCEPLocalException exceptionWithCode:FailedToEncodeSCEPMessage];
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
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
    }
}

-(MscSCEPResponse*)createAndSendSCEPMessageWithMessageType:(SCEPMessage)messageType transaction:(MscSCEPTransaction*)transaction error:(MscSCEPError**)error {
    
    @try {
        
        MscSCEPError* localError;
        _transaction = transaction;
        
        NSString* request = [self encodeSCEPMessageWithMessageType:messageType transaction:transaction error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        NSURL* url = [NSURL URLWithString: [NSString stringWithFormat:@"%@?operation=PKIOperation&message=%@", [transaction.scepServerURL absoluteString], [request urlencode]]];
        NSURLRequest* urlRequest = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:60.0];
        
        NSError* connectionError;
        NSLog(@"connection started to: %@", [url host]);
        NSData* payload = [NSURLConnection sendSynchronousRequest:urlRequest returningResponse:nil error:&connectionError];
        NSLog(@"connection finished");
        //MscHTTPSURLConnection* connection = [[MscHTTPSURLConnection alloc] init];
        //NSData* payload = [connection sendSynchronousRequest:urlRequest identity:nil identityPassword:nil returningResponse:nil validatorDelegate:validatorDelegate error:&connectionError];
        
        if (connectionError) {
            @throw [MscSCEPLocalException exceptionWithCode:connectionError.code];
        }
        
        MscSCEPResponse* scepResponse = [self decodeSCEPMessageWithTransaction:transaction responseData:payload requestMessageType:messageType error:&localError];
        if (localError) {
            @throw [MscSCEPLocalException exceptionWithCode:localError.code];
        }
        
        return scepResponse;
    }
    @catch (MscSCEPLocalException *e) {
        
        if (error) {
            *error = [MscSCEPError errorWithCode:e.errorCode];
        }
        return nil;
    }
}

@end
