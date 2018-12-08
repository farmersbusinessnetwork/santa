//
//  SNTSign.m
//  santactl
//
//  Created by Alexander Mohr on 12/4/18.
//

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#import "SNTConfigurator.h"
#include "SNTSign.h"
#import "SNTLogging.h"

@implementation Signing

+ (NSString *) hmac_sha256:(NSString *) key plaintext: (NSData *) plaintext {
    // Will output base64 encoded HMAC SHA256 of data encoded using key
    const char *cKey  = [key cStringUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), plaintext.bytes, plaintext.length, cHMAC);

    NSData *hash = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *base64Encoded = [hash base64EncodedStringWithOptions:0];
    
    return base64Encoded;
}

+ (NSString*) generate_signed_request_header:(NSURLRequest*) request {
    SNTConfigurator *config = [SNTConfigurator configurator];
    NSString* signing_key = [config syncClientAuthSigningSecret];
    if(!signing_key) {
      LOGD(@"Skipping auth due to missing secret");
      return NULL;
    }
  
    NSDictionary<NSString *, NSString *>* headers = [request allHTTPHeaderFields];
    NSArray* ordered_keys =  [[headers allKeys] sortedArrayUsingSelector:@selector(localizedCompare:)];
    NSMutableString* str_data = [NSMutableString string];
    
    // Add the URL path and method
    [str_data appendString:[NSString stringWithFormat:@"%@ %@", request.HTTPMethod, request.URL.path]];
    
    // Add URL query (if any)
    if(request.URL.query) {
        [str_data appendString:[NSString stringWithFormat:@"?%@",request.URL.query]];
    }
    
    // Add URL fragment (if any)
    if(request.URL.fragment) {
        [str_data appendString:[NSString stringWithFormat:@"#%@",request.URL.fragment]];
    }
    
    [str_data appendString:[NSString stringWithFormat:@"\n"]];
    
    // Add the headers
    // NOTE: this would break if you could have two of the same keys
    for (NSString* ordered_key in ordered_keys) {
      if([ordered_key caseInsensitiveCompare:@"Content-Type"] == NSOrderedSame) {
        // Unfortunately someone is appending ; charset="utf-8" to the value
        continue;
      }
      
      NSString* value = [headers objectForKey:ordered_key];
      [str_data appendString:[NSString stringWithFormat:@"%@=%@\n", ordered_key, value]];
    }
    
    NSMutableData* data = [[NSMutableData alloc] init];
    [data appendData: [[str_data lowercaseString] dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:request.HTTPBody];
    return [self hmac_sha256:signing_key plaintext:data];
}
@end
