//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework UserNotifications
#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>
#include <stdlib.h>

API_AVAILABLE(macos(10.14))
@interface GostpxNotificationDelegate : NSObject <UNUserNotificationCenterDelegate>
@end

@implementation GostpxNotificationDelegate

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions options))completionHandler API_AVAILABLE(macos(10.14)) {
    if (@available(macOS 11.0, *)) {
        completionHandler(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionList | UNNotificationPresentationOptionSound);
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        completionHandler(UNNotificationPresentationOptionAlert | UNNotificationPresentationOptionSound);
#pragma clang diagnostic pop
    }
}

@end

static GostpxNotificationDelegate *g_notificationDelegate = nil;

static inline BOOL hasBundleIdentifier(void) {
    NSBundle *bundle = [NSBundle mainBundle];
    if (bundle == nil) {
        return NO;
    }
    NSString *bundleID = [bundle bundleIdentifier];
    return (bundleID != nil && [bundleID length] > 0);
}

static inline void initNotificationsDarwin(void) {
    @autoreleasepool {
        if (!hasBundleIdentifier()) {
            return;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                if (@available(macOS 10.14, *)) {
                    @try {
                        UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
                        if (g_notificationDelegate == nil) {
                            g_notificationDelegate = [[GostpxNotificationDelegate alloc] init];
                        }
                        [center setDelegate:g_notificationDelegate];

                        UNAuthorizationOptions options = UNAuthorizationOptionAlert | UNAuthorizationOptionSound;
                        [center requestAuthorizationWithOptions:options
                                              completionHandler:^(BOOL granted, NSError * _Nullable error) {
                            if (error != nil) {
                                fprintf(stderr, "gostpx: ошибка авторизации уведомлений: %s\n",
                                        [[error localizedDescription] UTF8String]);
                            } else if (!granted) {
                                fprintf(stderr, "gostpx: уведомления не разрешены пользователем\n");
                            }
                        }];
                    } @catch (NSException *exception) {
                        fprintf(stderr, "gostpx: исключение при инициализации центра уведомлений: %s\n",
                                [[exception description] UTF8String]);
                    }
                }
            }
        });
    }
}

static inline void sendNotificationDarwin(const char *cTitle, const char *cBody) {
    @autoreleasepool {
        if (!hasBundleIdentifier()) {
            return;
        }
        if (@available(macOS 10.14, *)) {
            @try {
                // stringWithUTF8String returns nil on invalid UTF-8; content.title must not be nil.
                NSString *title = (cTitle ? [NSString stringWithUTF8String:cTitle] : nil) ?: @"gostpx";
                NSString *body = (cBody ? [NSString stringWithUTF8String:cBody] : nil) ?: @"";

                UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
                content.title = title;
                content.body = body;
                content.sound = [UNNotificationSound defaultSound];

                UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:@"gostpx.connection"
                                                                                      content:content
                                                                                      trigger:nil];

                UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
                [center addNotificationRequest:request withCompletionHandler:^(NSError * _Nullable error) {
                    if (error != nil) {
                        fprintf(stderr, "gostpx: ошибка отправки уведомления: %s\n",
                                [[error localizedDescription] UTF8String]);
                    }
                }];
            } @catch (NSException *exception) {
                fprintf(stderr, "gostpx: исключение при отправке уведомления: %s\n",
                        [[exception description] UTF8String]);
            }
        }
    }
}
*/
import "C"
import (
	"sync"
	"unsafe"
)

var notifyInitOnce sync.Once

func initNotifications() {
	if isSelftest() {
		return
	}
	notifyInitOnce.Do(func() {
		C.initNotificationsDarwin()
	})
}

func sendNotification(title, body string) {
	if isSelftest() {
		return
	}
	cTitle := C.CString(title)
	defer C.free(unsafe.Pointer(cTitle))
	cBody := C.CString(body)
	defer C.free(unsafe.Pointer(cBody))
	C.sendNotificationDarwin(cTitle, cBody)
}
