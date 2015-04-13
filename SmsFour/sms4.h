//
//  sms4.h
//  DEMo
//
//  Created by Bhavesh on 3/20/15.
//  Copyright (c) 2015 Bhavesh. All rights reserved.
//

typedef uint32_t unlong;

void setSMS4Key(unlong* key);
unlong *SMS4EncryptMain(unlong *psrc, size_t length);
unlong *SMS4DecryptMain(unlong *psrc, size_t length);