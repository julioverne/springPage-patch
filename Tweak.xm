#import <CommonCrypto/CommonHMAC.h>

@implementation NSString (Patch_by_julioverne)
+ (NSString *)encodeBase64WithString:(NSString *)strData {
    return [self encodeBase64WithData:[strData dataUsingEncoding:NSUTF8StringEncoding]];
}
+ (NSString*)encodeBase64WithData:(NSData*)theData {
    const uint8_t* input = (const uint8_t*)[theData bytes];
    NSInteger length = [theData length];

    static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    NSMutableData* data = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;

    NSInteger i;
    for (i=0; i < length; i += 3) {
        NSInteger value = 0;
        NSInteger j;
        for (j = i; j < (i + 3); j++) {
            value <<= 8;

            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }

        NSInteger theIndex = (i / 3) * 4;
        output[theIndex + 0] =                    table[(value >> 18) & 0x3F];
        output[theIndex + 1] =                    table[(value >> 12) & 0x3F];
        output[theIndex + 2] = (i + 1) < length ? table[(value >> 6)  & 0x3F] : '=';
        output[theIndex + 3] = (i + 2) < length ? table[(value >> 0)  & 0x3F] : '=';
    }

    return [[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] autorelease];
}
+ (NSString *)hmacSHA1BinBase64:(NSString *)data withKey:(NSString *)key 
{
    const char *cKey  = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cData = [data cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString *hash = [NSString encodeBase64WithData:HMAC];
	hash = [hash stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
	hash = [hash stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
	hash = [hash stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return hash;
}
@end


%hook NSURLConnection
+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {

 if ([[NSString stringWithFormat:@"%@", request] rangeOfString:@"cydia.saurik.com/api/check?"].location != NSNotFound)
 {
 if ([[NSString stringWithFormat:@"%@", request] rangeOfString:@"vendor=trinitus"].location != NSNotFound)
 {
 NSString *state = [NSString stringWithFormat:@"%@%@%@", [[[NSString stringWithFormat:@"%@", [[request URL] absoluteString]] componentsSeparatedByString:@"&"] objectAtIndex:3], @"&", @"state=completed"];
 NSString *response = [NSString stringWithFormat:@"%@%@%@", state, @"&signature=", [NSString hmacSHA1BinBase64:state withKey:@"583c14216416124b0f9e5dd0f10cdd23"]];
  return [response dataUsingEncoding:NSUTF8StringEncoding];
 }
 }
  return %orig(request, response, error);
}
%end