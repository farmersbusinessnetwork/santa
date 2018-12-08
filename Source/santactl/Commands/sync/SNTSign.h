//
//  SNTSign.h
//  santactl
//
//  Created by Alexander Mohr on 12/4/18.
//

#ifndef SNTSign_h
#define SNTSign_h

@interface Signing : NSObject

+ (NSString*) hmac_sha256:(NSString *)key plaintext:(NSData *)plaintext;
+ (NSString*) generate_signed_request_header:(NSURLRequest*) request;

@end

#endif /* SNTSign_h */
