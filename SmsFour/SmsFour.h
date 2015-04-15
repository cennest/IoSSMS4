//
//  SmsFour.h
//  SmsFour
//
//  Created by Bhavesh on 4/9/15.
//  Copyright (c) 2015 cennest. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 *  Before encryption or decryption task starts, libarary validates input arguments like fileSourcePath, fileDestinationPath etc.
 *  If invalid arguments passes while calling encryption or decryption methods then respective methods will send you back any of following error in completion block.
 */
typedef NS_ENUM(NSUInteger, SFErrorType){
    /**
     *  If source directory not found.
     */
    SFErrorSourceDirectoryNotFound = 401,
    /**
     *  If source or destination file path is null.
     */
    SFErrorPathIsNull = 402,
    /**
     *  If destination directory not found.
     */
    SFErrorDestinationDirectoryNotFound = 403,
    /**
     *  If destination file not found.
     */
    SFErrorSourceFileNotFound = 404,
    /**
     *  If data is nil.
     */
    SFErrorTypeSourceDataIsNil = 405
};

@interface SmsFour : NSObject
/**
 *  CompletionBlock is block, is used in encryption and decryption methods. *  Those methods call CompletionBlock, after encryption or description task is completed.
 *
 *  @param success Yes, if encryption or descryption task is completed without any error.
 *  @param error NSError will return, if encryption or description method's arguments are invalid.
 */
typedef void (^CompletionBlock)(BOOL success, NSError *error);

#pragma mark - Encryption Methods

/**
 *  This method encrypt sourcePath file and store encryption file in destinationPath.
 *
 *  @param sourcepath      Provide full file path with file name and extension, file should be available in given path otherwise method will send error message in completion block.
 *  @param key             SMS4's 128 bits key use in encryption task. if key is null, the method will use default key. NOTE: Use same key to decrypt file.
 *  @param destinationPath Encrypted data store in destinationPath, if nil, method will overwrite source file with encrypted data.
 *  @param callback        Callback is block, notifies that method completed encryption task. it has two parameters a)success: BOOL value, status of encryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)encryptFile:(NSString*)sourcePath withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callback;
/**
 *  This method encrypt sourcePath file and overwrite encryption file with the same sourcePath file.
 *
 *  @param filePath Provide full file path with file name and extension, file should be available in given path otherwise method will send error message in completion block.
 *  @param key      SMS4's 128 bits key use in encryption task. if key is null, the method will use default key. NOTE: Use same key to decrypt file.
 *  @param callback Callback is block, notifies that method completed encryption task. it has two parameters a)success: BOOL value, status of encryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)encryptFile:(NSString*)filePath withKey:(uint32_t*)key completion:(CompletionBlock)callback;
/**
 *  This method encrypts data and immediately returns encrypted data. For performance issue don't use large data, use method [encryptFile:withKey:saveFilePath:completion:] to encrypt large data file.
 *
 *  @param data send NSData, which you want to encrypt.
 *  @param key  SMS4's 128 bits key use in encryption task. if key is null, the method will use default key. NOTE: Use same key to decrypt file.
 *  @param destinationPath Encrypted data store in destinationPath, if nil, method will overwrite source file with encrypted data.
 *
 *  @return returns encrypted data of type NSData.
 */
-(NSData*)encryptData:(NSData*)data withKey:(uint32_t*)key;
/**
 *  This method encrypts data and saves encrypted data in destinationPath. For performance issue don't use large data, use method [encryptFile:withKey:saveFilePath:completion:] to encrypt large data file.
 *
 *  @param data            send NSData, which you want to encrypt. data should not be nil, otherwise method call callBack block with  error.
 *  @param key             SMS4's 128 bits key use in encryption task. if key is null, the method will use default key. NOTE: Use same key to decrypt file.
 *  @param destinationPath Encrypted data store in destinationPath, destinationPath should not nil, otherwise method call callBack block with SFErrorDestinationDirectoryNotFound error.
 *  @param callBack        Callback is block, notifies that method completed encryption task. it has two parameters a)success: BOOL value, status of encryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)encryptData:(NSData*)data withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callBack;
/**
 *  This method encrypt data of givien NSUrl and saves encrypted data in destinationPath.
 *
 *  @param fileUrl         Source file url.
 *  @param key             SMS4's 128 bits key use in encryption task. if key is null, the method will use default key. NOTE: Use same key to decrypt file.
 *  @param destinationPath Encrypted data store in destinationPath, destinationPath should not nil, otherwise method call callBack block with SFErrorDestinationDirectoryNotFound error.
 *  @param callBack        Callback is block, notifies that method completed encryption task. it has two parameters a)success: BOOL value, status of encryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)encryptFileFromUrl:(NSURL*)fileUrl withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callBack;

#pragma mark - Decryption Methods

/**
 *  This method decrypt sourcePath file and store decryption file in destinationPath.
 *
 *  @param sourcepath      Provide full file path with file name and extension, file should be available in given path otherwise method will send error message in completion block.
 *  @param key             Use the same key, which was used in ecryption task.
 *  @param destinationPath Decrypted data store in destinationPath, if nil, method will overwrite source file with decrypted data.
 *  @param callback        Callback is block, notifies that method completed decryption task. it has two parameter a)success: BOOL value, status of decryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)decryptFile:(NSString*)sourcePath withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callback;
/**
 *  This method decrypt sourcePath file and overwrite decryption file with the same sourcePath file.
 *
 *  @param filePath Provide full file path with file name and extension, file should be available in given path otherwise method will send error message in completion block.
 *  @param key      Use the same key, which was used in ecryption task.
 *  @param callback Callback is block, notifies that method completed decryption task. it has two parameter a)success: BOOL value, status of decryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)decryptFile:(NSString*)filePath withKey:(uint32_t*)key completion:(CompletionBlock)callback;
/**
 *  This method decrypts data and immediately returns decrypted data. For performance issue don't use large data, use method [decryptFile:withKey:saveFilePath:completion:] to decrypt large data file.
 *
 *  @param data send NSData, which you want to decrypt.
 *  @param key  Use the same key, which was used in ecryption task.
 *
 *  @return returns decrypted data of type NSData.
 */
-(NSData*)decryptData:(NSData*)data withKey:(uint32_t*)key;
/**
 *  This method decrypts data and saves decrypted data in destinationPath. For performance issue don't use large data, use method [decryptFile:withKey:saveFilePath:completion:] to decrypt large data file.
 *
 *  @param data            send NSData, which you want to decrypt.
 *  @param key             Use the same key, which was used in ecryption task.
 *  @param destinationPath Decrypted data store in destinationPath, destinationPath should not nil, otherwise method call callBack block with SFErrorDestinationDirectoryNotFound error.
 *  @param callBack        Callback is block, notifies that method completed decryption task. it has two parameters a)success: BOOL value, status of decryption task. b)error: NSError, description of error if problem occurs.
 */
-(void)decryptData:(NSData*)data withKey:(uint32_t*)key saveFilePath:(NSString*)destinationPath completion:(CompletionBlock)callBack;

#pragma mark - Create Function
/**
 *  Create SMS 4 key from NSString using SHA1 hash algorithms
 *
 *  @param keyString string key
 *
 *  @return SMS4 128 bit key crated using string key.
 */
-(uint32_t*)createKeyFormString:(NSString*)keyString;

@end
