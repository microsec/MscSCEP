//
//  MscCertificateUtils.m
//  MscSCEP
//
//  Created by Microsec on 2014.02.12..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscCertificateUtils.h"
#import <openssl/md5.h>
#import "MscLocalException.h"
#import "MscCertificateX509.h"
#import "MscCertificateSigningRequestX509_REQ.h"
#import "NSString+MscExtensions.h"

@implementation MscCertificateUtils

+(NSString*)getCertificatePublicKeyFingerPrint:(MscCertificate*)certificate error:(NSError**)error {
	
    unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
    
    @try {
        
        unsigned char *certificateData = NULL;
        long certificateDataLength = i2d_PUBKEY(X509_get_pubkey(certificate._x509), &certificateData);
        if (certificateDataLength < 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to read certificate BIO, function i2d_PUBKEY returned with: %ld", certificateDataLength]}];
        }
        
        MD5_Init(&ctx);
        MD5_Update(&ctx, certificateData, certificateDataLength);
        MD5_Final(hash, &ctx);
        
        NSMutableString *result = [[NSMutableString alloc] initWithCapacity: MD5_DIGEST_LENGTH * 2];
        
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            [result appendFormat:@"%02X", hash[i]];
        }
        
        return result;
    }
    @catch (MscLocalException *e) {
        *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        return nil;
    }
}


+(NSString*)getCertificateSigningRequestPublicKeyFingerPrint:(MscCertificateSigningRequest*)request error:(NSError**)error {
    
    unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
    
    @try {
        
        unsigned char *requestData = NULL;
        long requestDataLength = i2d_PUBKEY(X509_REQ_get_pubkey(request._request), &requestData);
        if (requestDataLength < 1) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToReadCertificate errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to read certificate BIO, function i2d_PUBKEY returned with: %ld", requestDataLength]}];
        }
        
        MD5_Init(&ctx);
        MD5_Update(&ctx, requestData, requestDataLength);
        MD5_Final(hash, &ctx);
        
        NSMutableString *result = [[NSMutableString alloc] initWithCapacity: MD5_DIGEST_LENGTH * 2];
        
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            [result appendFormat:@"%02X", hash[i]];
        }
        
        return result;
    }
    @catch (MscLocalException *e) {
        *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        return nil;
    }
}

+(X509_NAME*)convertMscCertificateSubjectToX509_NAME:(MscCertificateSubject*)subject error:(NSError**)error {
    
    X509_NAME* name = NULL;
    
    @try {
        
        int returnCode;
        
        name = X509_NAME_new();
        if (!name) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToAllocateMemory errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to allocate memory for variable: requestBio"}];
        }
        
        if (subject.commonName && ![subject.commonName isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8, (unsigned char*)[subject.commonName UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.localityName && ![subject.localityName isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_UTF8, (unsigned char*)[subject.localityName UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.stateOrProvinceName && ![subject.stateOrProvinceName isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_UTF8, (unsigned char*)[subject.stateOrProvinceName UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.organizationName && ![subject.organizationName isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_UTF8, (unsigned char*)[subject.organizationName UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.organizationalUnitName && ![subject.organizationalUnitName isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_UTF8, (unsigned char*)[subject.organizationalUnitName UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.countryName && ![subject.countryName isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_UTF8, (unsigned char*)[subject.countryName UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.streetAddress && ![subject.streetAddress isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_streetAddress, MBSTRING_UTF8, (unsigned char*)[subject.streetAddress UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.domainComponent && ![subject.domainComponent isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_domainComponent, MBSTRING_UTF8, (unsigned char*)[subject.domainComponent UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        if (subject.userid && ![subject.userid isEmpty]) {
            returnCode = X509_NAME_add_entry_by_NID(name, NID_userId, MBSTRING_UTF8, (unsigned char*)[subject.userid UTF8String], -1, -1, 0);
            if (returnCode != 1) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function X509_NAME_add_entry_by_NID returned with %d", returnCode]}];
            }
        }
        return name;
    }
    @catch (MscLocalException *e) {
        
        X509_NAME_free(name);
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
    
}

+(MscCertificateSubject*)convertX509_NAMEToMscCertificateSubject:(X509_NAME*)name error:(NSError**)error {
    
    @try {
        
        NSError* error;
        
        MscCertificateSubject* subject = [[MscCertificateSubject alloc] init];
        
        subject.commonName = [self getX509NameEntryWithNid:NID_commonName x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.localityName = [self getX509NameEntryWithNid:NID_localityName x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.stateOrProvinceName = [self getX509NameEntryWithNid:NID_stateOrProvinceName x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.organizationName = [self getX509NameEntryWithNid:NID_organizationName x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.organizationalUnitName = [self getX509NameEntryWithNid:NID_organizationalUnitName x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.countryName = [self getX509NameEntryWithNid:NID_countryName x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.streetAddress = [self getX509NameEntryWithNid:NID_streetAddress x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.domainComponent = [self getX509NameEntryWithNid:NID_domainComponent x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        subject.userid = [self getX509NameEntryWithNid:NID_userId x509Name:name error:&error];
        if (nil != error) {
            @throw [[MscLocalException alloc] initWithErrorCode:error.code errorUserInfo:error.userInfo];
        }
        
        return subject;
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
}

+(NSString*)getX509NameEntryWithNid:(int)nid x509Name:(X509_NAME*)x509Name error:(NSError**)error{
    
    unsigned char* buffer = NULL;
    
    @try {
        
        int returnCode;
        
        returnCode = X509_NAME_get_index_by_NID(x509Name, nid, -1);
        if (returnCode != -1) {
            ASN1_STRING* asn1String = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(x509Name, returnCode));
            if (!asn1String) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to convert certificate subject, function: X509_NAME_ENTRY_get_data"}];
            }
            returnCode = ASN1_STRING_to_UTF8(&buffer, asn1String);
            if (returnCode < 0) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertCertificateSubject errorUserInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat: @"Failed to convert certificate subject, function ASN1_STRING_to_UTF8 returned with %d", returnCode]}];
            }
            return [NSString stringWithCString:(const char*)buffer encoding:NSUTF8StringEncoding];
        }
        else {
            return nil;
        }
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
    @finally {
        OPENSSL_free(buffer);
    }
}

+(NSString*)convertASN1_INTEGERToNSString:(ASN1_INTEGER*)serialNumber error:(NSError**)error {
    
    BIGNUM* bigNumer = NULL;
    
    @try {

        bigNumer = ASN1_INTEGER_to_BN(serialNumber, NULL);
        if (!bigNumer) {
                @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertSerialNumber errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to convert serial number, function: ASN1_INTEGER_to_BN"}];
        }
        
        return [[NSString alloc] initWithCString:BN_bn2hex(bigNumer) encoding:NSASCIIStringEncoding];
    }
    @catch (MscLocalException *e) {
        
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
    @finally {
        
        BN_free(bigNumer);
    }
}

+(ASN1_INTEGER*)convertNSStringToASN1_INTEGER:(NSString*)serialNumber error:(NSError**)error {
    
    ASN1_INTEGER* serial = NULL;
    BIGNUM* bigNumber = NULL;
    
    @try {

        BN_hex2bn(&bigNumber, [serialNumber ASCIIString]);
        if (!bigNumber) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertSerialNumber errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to convert serial number, function: BN_hex2bn"}];
        }
        
        serial = BN_to_ASN1_INTEGER(bigNumber, NULL);
        if (!serial) {
            @throw [[MscLocalException alloc] initWithErrorCode:FailedToConvertSerialNumber errorUserInfo:@{NSLocalizedDescriptionKey: @"Failed to convert serial number, function: BN_to_ASN1_INTEGER"}];
        }
        
        return serial;
        
    }
    @catch (MscLocalException *e) {
        
        ASN1_INTEGER_free(serial);
        if (error) {
            *error = [NSError errorWithDomain:e.errorDomain code:e.errorCode userInfo:e.errorUserInfo];
        }
        return nil;
    }
    @finally {
        
        BN_free(bigNumber);
    }
}

@end
