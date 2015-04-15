//
//  SmsFour.m
//  SmsFour
//
//  Created by Bhavesh on 4/9/15.
//  Copyright (c) 2015 cennest. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>

#import "SmsFour.h"
#import "sms4.h"


static NSUInteger const kFileLimit = 8000000;

static NSString* const kcSMSFourErrorDomain = @"SMSFourErrorDomain";

static NSString* const kcSourceDirectoryErrorDescription = @"Source Directory not found.";
static NSString* const kcDirectoryErrorReason = @"%@ not such path present.";
static NSString* const kcDirectoryErrorSuggestion = @"Make sure provided directory path is right.";

static NSString* const kcPathIsNullErrorDescription = @"Directory path is Null.";
static NSString* const kcPathIsNullErrorReason = @"";
static NSString* const kcPathIsNullErrorSuggestion = @"Provide full file Path.";

static NSString* const kcDestinationDirectoryErrorDescription = @"Source Directory not found.";

static NSString* const kcFileNotFoundErrorDescription = @"File not found.";
static NSString* const kcFileNotFoundErrorReason = @"%@ not such path found.";
static NSString* const kcFileNotFoundErrorSuggestion = @"Make sure provided file path is right.";

static NSString* const kcDataIsNilErrorDescription = @"Data is nil.";
static NSString* const kcDataIsNilErrorSuggestion = @"Try to provide data some value.";

@implementation SmsFour

#pragma mark - Encryption Methods

-(void)encryptFile:(NSString*)sourcePath withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callback
{
    if (destinationPath == nil) {
        destinationPath = sourcePath;
    }
    NSError* error = [self validateForSourceFile:sourcePath destinationPath:destinationPath];
    if (error) {
        if (callback) {
            callback(NO,error);
        }
        return;
    }
    setSMS4Key(key);
    unsigned long long fileSize =[self getFileSize:sourcePath];
    if (fileSize <= kFileLimit) {
        NSError *fileLoadError = nil;
        NSData* fileData = [NSData dataWithContentsOfFile:sourcePath options:NSDataReadingMappedIfSafe error:&fileLoadError];
        if (fileLoadError) {
            if (callback) {
                callback(NO,fileLoadError);
            }
            
            return;
        }
        NSData* encryptedData = [self getEncryptData:fileData lastSlot:YES];
        [self saveFile:encryptedData location:destinationPath];
    } else {
        __weak typeof(self) weakSelf = self;
        void (^encryptAndSaveSlot)(unsigned long long, NSString*, NSString*,NSUInteger,BOOL) = ^(unsigned long long offset, NSString* sourcePath, NSString* destinationPath, NSUInteger length,BOOL isLastSlot){
            NSData* data = [weakSelf readBytes:length ofOffset:offset fromFile:sourcePath];
            NSData* encryptedData = [weakSelf getEncryptData:data lastSlot:isLastSlot];
            [weakSelf writeData:encryptedData ofOffset:offset fromFile:destinationPath];
        };
        
        NSUInteger completeSlotCount = (NSUInteger)fileSize/kFileLimit;
        NSUInteger lastSlotBytesCount = (NSUInteger)fileSize%kFileLimit;
        unsigned long long offset = 0;
        for (int slotCount = 0; slotCount < completeSlotCount; slotCount++) {
            @autoreleasepool {
                encryptAndSaveSlot(offset,sourcePath,destinationPath,kFileLimit,NO);
                offset = offset + kFileLimit;
            }
        }
        if (lastSlotBytesCount>0) {
            encryptAndSaveSlot(offset,sourcePath,destinationPath,lastSlotBytesCount, YES);
        }
    }
    if (callback) {
        callback(YES,error);
    }
}

-(NSData*)encryptData:(NSData*)data withKey:(uint32_t*)key
{
    if (data == nil) {
        return nil;
    }
    setSMS4Key(key);
    NSData* encryptedData = [self getEncryptData:data lastSlot:YES];
    return encryptedData;
}

-(void)encryptData:(NSData *)data withKey:(uint32_t *)key saveFilePath:(NSString *)destinationPath completion:(CompletionBlock)callBack
{
    NSError* error = nil;
    if (data == nil) {
        error = [self createErrorForDescription:kcDataIsNilErrorDescription errorCode:SFErrorTypeSourceDataIsNil reason:nil suggestion:kcDataIsNilErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    if (destinationPath == nil) {
        error = [self createErrorForDescription:kcDestinationDirectoryErrorDescription errorCode:SFErrorPathIsNull reason:kcPathIsNullErrorReason suggestion:kcDirectoryErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    if ([self validateFolder:destinationPath] == NO) {
        error = [self createErrorForDescription:kcDestinationDirectoryErrorDescription errorCode:SFErrorDestinationDirectoryNotFound reason:[NSString stringWithFormat:kcDirectoryErrorReason,destinationPath] suggestion:kcDirectoryErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    setSMS4Key(key);
    NSData* encryptedData = [self getEncryptData:data lastSlot:YES];
    [self saveFile:encryptedData location:destinationPath];
    if (callBack) {
        callBack(YES,error);
    }
}

-(void)encryptFile:(NSString*)filePath withKey:(uint32_t*)key completion:(CompletionBlock)callback
{
    NSString* destinationPath = filePath;
    [self encryptFile:filePath withKey:key saveFilePath:destinationPath completion:callback];
}

-(void)encryptFileFromUrl:(NSURL*)fileUrl withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callBack
{
    NSError* error = nil;
    if (destinationPath == nil) {
        error = [self createErrorForDescription:kcDestinationDirectoryErrorDescription errorCode:SFErrorPathIsNull reason:kcPathIsNullErrorReason suggestion:kcDirectoryErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    NSNumber *fileSizeValue = nil;
    NSError *fileSizeError = nil;
    [fileUrl getResourceValue:&fileSizeValue forKey:NSURLFileSizeKey error:&fileSizeError];
    if (fileSizeError) {
        callBack(NO,fileSizeError);
    }
    setSMS4Key(key);
    NSUInteger fileSize = [fileSizeValue unsignedIntegerValue];
    if (fileSize <= kFileLimit) {
        NSError *fileLoadError = nil;
        NSData* fileData = [NSData dataWithContentsOfURL:fileUrl options:NSDataReadingMappedIfSafe error:&fileLoadError];
        if (fileLoadError) {
            if (callBack) {
                callBack(NO,fileLoadError);
            }
            return;
        }
        NSData* encryptedData = [self getEncryptData:fileData lastSlot:YES];
        [self saveFile:encryptedData location:destinationPath];
    } else {
        __weak typeof(self) weakSelf = self;
        void (^encryptAndSaveSlot)(unsigned long long, NSURL*, NSString*,NSUInteger,BOOL) = ^(unsigned long long offset, NSURL* url, NSString* destinationPath, NSUInteger length,BOOL isLastSlot){
            NSData* data = [weakSelf readBytes:length ofOffset:offset fromFileUrl:url];
            NSData* encryptedData = [weakSelf getEncryptData:data lastSlot:isLastSlot];
            [weakSelf writeData:encryptedData ofOffset:offset fromFile:destinationPath];
        };
        
        NSUInteger completeSlotCount = (NSUInteger)fileSize/kFileLimit;
        NSUInteger lastSlotBytesCount = (NSUInteger)fileSize%kFileLimit;
        unsigned long long offset = 0;
        for (int slotCount = 0; slotCount < completeSlotCount; slotCount++) {
            @autoreleasepool {
                encryptAndSaveSlot(offset,fileUrl,destinationPath,kFileLimit,NO);
                offset = offset + kFileLimit;
            }
        }
        if (lastSlotBytesCount>0) {
            encryptAndSaveSlot(offset,fileUrl,destinationPath,lastSlotBytesCount, YES);
        }

    }
    if (callBack) {
        callBack(YES,error);
    }
}

#pragma mark - Encryption helper Methods

-(NSData*)getEncryptData:(NSData*)data lastSlot:(BOOL)isLastSlot
{
    uint32_t* uIntArray = [self wrapArrayForData:data];
    NSUInteger paddedDataLength = [self getSizeAfterPadding:data.length];
    SMS4EncryptMain(uIntArray, paddedDataLength);
    NSData* encryptedData = [self unWrappEncryptedArray:uIntArray ofLength:paddedDataLength extraPadding:[self getExtraPaddingCountForActualLength:data.length] lastSlot:isLastSlot];
    free(uIntArray);
    return encryptedData;
}

#pragma mark - Decryption Methods

-(void)decryptFile:(NSString*)sourcePath withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callback
{
    if (destinationPath == nil) {
        destinationPath = sourcePath;
    }
    NSError* error = [self validateForSourceFile:sourcePath destinationPath:destinationPath];
    if (error) {
        if (callback) {
            callback(NO,error);
        }
        return;
    }
    setSMS4Key(key);
    unsigned long long fileSize =[self getFileSize:sourcePath];
    if (fileSize <= kFileLimit+1) {
        NSError* fileLoadError = nil;
        NSData *encryptData =[NSData dataWithContentsOfFile:sourcePath options:NSDataReadingMappedIfSafe error:&fileLoadError];
        if (fileLoadError) {
            if (callback) {
                callback(NO,fileLoadError);
            }
            
            return;
        }
        NSData* decryptedData =  [self getDecryptData:encryptData lastSlot:YES];
        [self saveFile:decryptedData location:destinationPath];
    } else {
        __weak typeof(self) weakSelf = self;
        void (^decryptAndSaveSlot)(unsigned long long, NSString*, NSString*,NSUInteger, BOOL) = ^(unsigned long long offset, NSString* sourcePath, NSString* destinationPath,NSUInteger length, BOOL isLastSlot){
            NSData* data = [weakSelf readBytes:length ofOffset:offset fromFile:sourcePath];
            NSData* decryptedData = nil;
            if (isLastSlot) {
                decryptedData = [weakSelf getDecryptData:data lastSlot:YES];
            } else {
                decryptedData = [weakSelf getDecryptData:data lastSlot:NO];
            }
            [weakSelf writeData:decryptedData ofOffset:offset fromFile:destinationPath];
        };
        NSUInteger completeSlotCount = (NSUInteger)fileSize/kFileLimit;
        NSUInteger lastSlotBytesCount = (NSUInteger)fileSize%kFileLimit;
        unsigned long long offset = 0;
        for (int slotCount = 0; slotCount < completeSlotCount; slotCount++) {
            @autoreleasepool {
                decryptAndSaveSlot(offset,sourcePath,destinationPath,kFileLimit,NO);
                offset = offset + kFileLimit;
            }
            
        }
        if (lastSlotBytesCount>0) {
            decryptAndSaveSlot(offset,sourcePath,destinationPath,lastSlotBytesCount,YES);
        }
    }
    if (callback) {
        callback(YES,error);
    }
}

-(void)decryptFile:(NSString*)filePath withKey:(uint32_t*)key completion:(CompletionBlock)callback
{
    NSString* destinationPath = filePath;
    [self decryptFile:filePath withKey:key saveFilePath:destinationPath completion:callback];
}

-(NSData*)decryptData:(NSData*)data withKey:(uint32_t*)key
{
    if (data == nil) {
        return nil;
    }
    setSMS4Key(key);
    NSData* encryptedData = [self getDecryptData:data lastSlot:YES];
    return encryptedData;
}

-(void)decryptData:(NSData *)data withKey:(uint32_t *)key saveFilePath:(NSString *)destinationPath completion:(CompletionBlock)callBack
{
    NSError* error = nil;
    if (data == nil) {
        error = [self createErrorForDescription:kcDataIsNilErrorDescription errorCode:SFErrorTypeSourceDataIsNil reason:nil suggestion:kcDataIsNilErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    if (destinationPath == nil) {
        error = [self createErrorForDescription:kcDestinationDirectoryErrorDescription errorCode:SFErrorPathIsNull reason:kcPathIsNullErrorReason suggestion:kcDirectoryErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    if ([self validateFolder:destinationPath] == NO) {
        error = [self createErrorForDescription:kcDestinationDirectoryErrorDescription errorCode:SFErrorDestinationDirectoryNotFound reason:[NSString stringWithFormat:kcDirectoryErrorReason,destinationPath] suggestion:kcDirectoryErrorSuggestion];
        if (callBack) {
            callBack(NO,error);
        }
        return;
    }
    setSMS4Key(key);
    NSData* decryptedData =  [self getDecryptData:data lastSlot:YES];
    [self saveFile:decryptedData location:destinationPath];
    if (callBack) {
        callBack(YES,error);
    }
}

#pragma mark - Decryption helper Methods

-(NSData*)getDecryptData:(NSData*)data lastSlot:(BOOL)isLastSlot
{
    NSUInteger length = [data length];
    Byte *byteData = (Byte*)malloc(length);
    memcpy(byteData, [data bytes], length);
    NSUInteger extraPadding= 0;
    if (isLastSlot) {
        extraPadding =  byteData[length-1];
        length--;
    }
    uint32_t *uIntArray = (uint32_t*)malloc(length);
    NSUInteger size = length/4;
    NSUInteger lastDataCount=0;
    memset(uIntArray, 0, length);
    //int compltIttreation = (int)(len/4);
    for (int i=0; i < size ; i++) {
        uint32_t result = ((uint32_t)byteData[lastDataCount]<<24) | ((uint32_t)byteData[lastDataCount+1]<<16)| ((uint32_t)byteData[lastDataCount+2]<<8) | (uint32_t)byteData[lastDataCount+3];
        uIntArray[i]=result;
        lastDataCount=lastDataCount+4;
    }
    
    SMS4DecryptMain(uIntArray, length);
    NSData* decryptedData = [self unWrappDecryptedArray:uIntArray paddingCount:extraPadding dataLenght:length];
    free(uIntArray);
    free(byteData);
    return decryptedData;
}

#pragma mark - Validation Methods

-(NSError*)validateForSourceFile:(NSString*)sourcePath destinationPath:(NSString*)destinationPath
{
    //Validation 1):- Path shouldn't be nil.
    BOOL success = YES;
    NSError* error = nil;
    if (sourcePath == nil || destinationPath == nil) {
        error = [self createErrorForDescription:kcPathIsNullErrorDescription errorCode:SFErrorPathIsNull reason:kcPathIsNullErrorReason suggestion:kcDirectoryErrorSuggestion];
        success = NO;
        return error;
    }
    //Validation 2):- Make sure source directory is present.
    success = [self validateFolder:sourcePath];
    if(success == NO)
    {
        error = [self createErrorForDescription:kcSourceDirectoryErrorDescription errorCode:SFErrorSourceDirectoryNotFound reason:[NSString stringWithFormat:kcDirectoryErrorReason,sourcePath] suggestion:kcDirectoryErrorSuggestion];
        return error;
    }
    //Validation 3):- Make sure destination directory is present.
    success = [self validateFolder:destinationPath];
    if(success == NO)
    {
        error = [self createErrorForDescription:kcDestinationDirectoryErrorDescription errorCode:SFErrorDestinationDirectoryNotFound reason:[NSString stringWithFormat:kcDirectoryErrorReason,destinationPath] suggestion:kcDirectoryErrorSuggestion];
        return error;
    }
    //Validation 4):- Make sure source file is present.
    success = [self validateFile:sourcePath];
    if(success == NO)
    {
        error = [self createErrorForDescription:kcFileNotFoundErrorDescription errorCode:SFErrorSourceFileNotFound reason:[NSString stringWithFormat:kcFileNotFoundErrorReason,sourcePath] suggestion:kcFileNotFoundErrorSuggestion];
        return error;
    }
    return error;
    
}

-(BOOL)validateFolder:(NSString*)filePath
{
    NSString* fileName = [[filePath componentsSeparatedByString:@"/"] lastObject];
    NSString* directoryPath = [filePath stringByReplacingOccurrencesOfString:fileName withString:@""];
    BOOL isDir = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:directoryPath isDirectory:&isDir])
    {
        if (isDir==YES) {
            return YES;
        }
    }
    return NO;
}

-(BOOL)validateFile:(NSString*)filePath
{
    if ([[NSFileManager defaultManager] fileExistsAtPath:filePath])
    {
        return YES;
    }
    return NO;
}

#pragma mark - Misc. Methods

-(unsigned long long)getFileSize:(NSString*)filePath
{
    NSError* err = nil;
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:&err];
    unsigned long long fileSize = [attributes fileSize];
    return fileSize;
}

-(NSUInteger)getSizeAfterPadding:(NSUInteger)dataLength
{
    NSUInteger paddingNumber = [self getExtraPaddingCountForActualLength:dataLength];
    NSUInteger length = dataLength + paddingNumber;
    return length;
}

-(NSUInteger)getExtraPaddingCountForActualLength:(NSUInteger)actualLength
{
    NSUInteger extraCount = actualLength%16;
    if (extraCount==0) {
        return 0;
    }
    NSUInteger paddingNumber = 16 - extraCount;
    return paddingNumber;
}

-(uint32_t*)wrapArrayForData:(NSData*)data
{
    NSUInteger dataLength = [data length];
    NSUInteger byteLengthAfterPadding = [self getSizeAfterPadding:dataLength];
    Byte *byteData = (Byte*)malloc(byteLengthAfterPadding);
    int extraPaddingCount = (int)[self getExtraPaddingCountForActualLength:dataLength];
    memset(byteData, extraPaddingCount, byteLengthAfterPadding+1);
    memcpy(byteData, [data bytes], dataLength);
    size_t size = byteLengthAfterPadding/4;
    uint32_t *uIntArray = (uint32_t*)malloc(byteLengthAfterPadding);
    memset(uIntArray, 0, byteLengthAfterPadding);
    int lastByteIndex=0;
    for (int i=0; i < size ; i++) {
        uint32_t result = ((uint32_t)byteData[lastByteIndex]<<24) | ((uint32_t)byteData[lastByteIndex+1]<<16)| ((uint32_t)byteData[lastByteIndex+2]<<8) | (uint32_t)byteData[lastByteIndex+3];
        uIntArray[i]=result;
        lastByteIndex=lastByteIndex+4;
    }
    free(byteData);
    return uIntArray;
}

-(NSData*)unWrappEncryptedArray:(uint32_t*)dataArray ofLength:(NSUInteger)dataLength extraPadding:(NSUInteger)extraPadding lastSlot:(NSUInteger)isLastSlot
{
    if (isLastSlot) {
        dataLength++;
    }
    Byte *newByteData = (Byte*)malloc(dataLength);
    memset(newByteData, 0, dataLength);
    int newByteCount = 0;
    for (int i=0; i<dataLength/4; i++) {
        uint32_t number = dataArray[i];
        unsigned int fourth = number & 0xff;
        unsigned int third = (number>>8) & 0xff;
        unsigned int second = (number>>16) & 0xff;
        unsigned int first = (number>>24) & 0xff;
        newByteData[newByteCount] = first;
        newByteCount++;
        newByteData[newByteCount] = second;
        newByteCount++;
        newByteData[newByteCount] = third;
        newByteCount++;
        newByteData[newByteCount] = fourth;
        newByteCount++;
    }
    if (isLastSlot) {
        newByteData[newByteCount]=extraPadding;
    }
    
    NSData* encryptData =[NSData dataWithBytesNoCopy:newByteData length:dataLength freeWhenDone:YES];
    //free(newByteData);
    return encryptData;
}

-(void)saveFile:(NSData*)data location:(NSString*)location
{
    [data writeToFile:location atomically:YES];
}

-(NSData*)readBytes:(NSUInteger)length ofOffset:(unsigned long long)offset fromFile:(NSString*)filePath
{
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    [fileHandle seekToFileOffset:offset];
    NSData *data = [fileHandle readDataOfLength:length];
    return data;
}

-(NSData*)readBytes:(NSUInteger)length ofOffset:(unsigned long long)offset fromFileUrl:(NSURL*)url
{
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingFromURL:url error:nil];
    [fileHandle seekToFileOffset:offset];
    NSData *data = [fileHandle readDataOfLength:length];
    return data;
}

-(void)writeData:(NSData*)data ofOffset:(unsigned long long)offset fromFile:(NSString*)filePath
{
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:filePath];
    if (!fileExists) {
        [data writeToFile:filePath atomically:YES];
    } else {
        NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
        [fileHandle seekToFileOffset:offset];
        [fileHandle writeData:data];
    }
    
}

-(NSData*)unWrappDecryptedArray:(uint32_t*)dataArray paddingCount:(NSUInteger)paddingCount dataLenght:(NSUInteger)dataLenght
{
    Byte *newByteData = (Byte*)malloc(dataLenght);
    memset(newByteData, 0, dataLenght);
    
    int newByteCount = 0;
    for (int i=0; i<dataLenght/4; i++) {
        uint32_t number = dataArray[i];
        unsigned int fourth = number & 0xff;
        unsigned int third = (number>>8) & 0xff;
        unsigned int second = (number>>16) & 0xff;
        unsigned int first = (number>>24) & 0xff;
        newByteData[newByteCount] = first;
        newByteCount++;
        newByteData[newByteCount] = second;
        newByteCount++;
        newByteData[newByteCount] = third;
        newByteCount++;
        newByteData[newByteCount] = fourth;
        newByteCount++;
    }
    //Remove extra data
    dataLenght = dataLenght-paddingCount;
    NSData* decryptedData =[NSData dataWithBytesNoCopy:newByteData length:dataLenght freeWhenDone:YES];
    //free(newByteData);
    return decryptedData;
}

-(NSError*)createErrorForDescription:(NSString*)description errorCode:(SFErrorType)code reason:(NSString*)reason suggestion:(NSString*)suggestion
{
    NSDictionary *userInfo = @{
                               NSLocalizedDescriptionKey: description,
                               NSLocalizedFailureReasonErrorKey: reason,
                               NSLocalizedRecoverySuggestionErrorKey: suggestion
                               };
    NSError *error = [NSError errorWithDomain:kcSMSFourErrorDomain
                                         code:code
                                     userInfo:userInfo];
    return error;
}

#pragma mark - Create SMS4 key

-(uint32_t*)createKeyFormString:(NSString*)keyString
{
    //Refer following link.
    //http://stackoverflow.com/questions/18122192/custom-string-to-128-bit-string and http://stackoverflow.com/questions/16059594/sha1-hash-producing-different-result-in-objective-c-and-c-net
    const char* cString = [keyString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData* data1 = [NSData dataWithBytes:cString length:keyString.length];
    uint8_t hash [CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data1.bytes, data1.length, hash);
    size_t size = sizeof(uint32_t)*4;
    uint32_t *keyArray = (uint32_t*)malloc(size);
    memset(keyArray, 0, size);
    int lastByteIndex=0;
    for (int i=0; i < 4 ; i++) {
        uint32_t result = (hash[lastByteIndex]<<24) | (hash[lastByteIndex+1]<<16)| (hash[lastByteIndex+2]<<8) | hash[lastByteIndex+3];
        keyArray[i]=result;
        lastByteIndex=lastByteIndex+4;
    }
    return keyArray;
}

@end
