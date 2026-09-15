#import "MoneroModule.h"
#include "monero-methods.hpp"

@interface MoneroModule () {
  dispatch_queue_t _moneroQueue;
  dispatch_queue_t _nymCompletionQueue;
}
@end

static bool isNymCompletionMethod(const std::string& method) {
  return method == "resolveFetch" || method == "rejectFetch";
}

// Global pointer so the C++ callback can reach the ObjC module instance
static __weak MoneroModule* g_module = nil;

// The wallet files (the wallet2 cache with transaction history and key images,
// plus .keys) live in Documents, which iOS backs up to iCloud by default. They
// are named "<backend>_<walletId>" with .keys/.address.txt siblings, so the id
// sits mid-name and has to be matched by containment. Re-applied on every write
// because store() renames a fresh, unflagged file into place.
static void excludeWalletFilesFromBackup(const std::string& walletId) {
  if (walletId.empty()) return;
  NSString *needle = [NSString stringWithUTF8String:walletId.c_str()];
  if (needle == nil || needle.length == 0) return;

  NSFileManager *fm = [NSFileManager defaultManager];
  NSURL *docsDir = [fm URLForDirectory:NSDocumentDirectory
                             inDomain:NSUserDomainMask
                    appropriateForURL:nil
                               create:NO
                                error:nil];
  if (docsDir == nil) return;

  NSArray<NSURL *> *items =
    [fm contentsOfDirectoryAtURL:docsDir
     includingPropertiesForKeys:nil
                        options:NSDirectoryEnumerationSkipsSubdirectoryDescendants
                          error:nil];
  for (NSURL *item in items) {
    if ([[item lastPathComponent] rangeOfString:needle].location == NSNotFound) {
      continue;
    }
    [item setResourceValue:@YES
                    forKey:NSURLIsExcludedFromBackupKey
                     error:nil];
  }
}

@implementation MoneroModule

RCT_EXPORT_MODULE(MoneroLwsfModule);

+ (BOOL)requiresMainQueueSetup { return NO; }

- (instancetype)init {
  self = [super init];
  if (self) {
    g_module = self;
    _moneroQueue = dispatch_queue_create(
      "app.edge.rnmonero.monero", DISPATCH_QUEUE_SERIAL);
    _nymCompletionQueue = dispatch_queue_create(
      "app.edge.rnmonero.nymCompletion", DISPATCH_QUEUE_SERIAL);

    // Wire the C++ wallet-event callback to this module's event emitter
    moneroSetEventCallback([](const std::string& walletId,
                              const std::string& eventName,
                              const std::string& jsonPayload) {
      MoneroModule* module = g_module;
      if (module == nil) return;

      NSString *nsWalletId  = [NSString stringWithUTF8String:walletId.c_str()];
      NSString *nsEventName = [NSString stringWithUTF8String:eventName.c_str()];
      NSString *nsPayload   = [NSString stringWithUTF8String:jsonPayload.c_str()];

      dispatch_async(dispatch_get_main_queue(), ^{
        [module sendEventWithName:@"MoneroWalletEvent" body:@{
          @"walletId":  nsWalletId,
          @"eventName": nsEventName,
          @"data":      nsPayload
        }];
      });
    });

    // Keep the wallet cache and keys out of iCloud backups. Fires on the SDK
    // refresh thread for the periodic stores during sync, which is fine:
    // NSFileManager and setResourceValue: are thread-safe.
    moneroSetWalletFilesChangedCallback([](const std::string& walletId) {
      excludeWalletFilesFromBackup(walletId);
    });
  }
  return self;
}

- (NSArray<NSString *> *)supportedEvents {
  return @[@"MoneroWalletEvent"];
}

- (void)startObserving {}
- (void)stopObserving {}

RCT_REMAP_METHOD(
  callMonero,
  callMoneroMethod:(NSString *)method
  arguments:(NSArray *)arguments
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
) {
  const std::string methodString = [method UTF8String];

  // Re-package the arguments:
  NSUInteger length = [arguments count];
  std::vector<std::string> strings;
  strings.reserve(length);
  for (NSUInteger i = 0; i < length; ++i) {
    NSString *string = [arguments objectAtIndex:i];
    strings.push_back([string UTF8String]);
  }

  // Find the named method:
  for (int i = 0; i < moneroMethodCount; ++i) {
    if (moneroMethods[i].name != methodString) continue;

    // Validate the argument count:
    if (moneroMethods[i].argc != strings.size()) {
      reject(@"Error", @"monero incorrect C++ argument count", nil);
      return;
    }

    const MoneroMethod methodInfo = moneroMethods[i];
    dispatch_queue_t queue =
      isNymCompletionMethod(methodString) ? _nymCompletionQueue : _moneroQueue;
    dispatch_async(queue, ^{
      // Call the method, with error handling:
      try {
        const std::string out = methodInfo.method(strings);
        resolve(
          [NSString stringWithCString:out.c_str() encoding:NSUTF8StringEncoding]
        );
      } catch (std::exception &e) {
        reject(
          @"Error",
          [NSString stringWithCString:e.what() encoding:NSUTF8StringEncoding],
          nil
        );
      } catch (...) {
        reject(@"Error", @"monero threw a C++ exception", nil);
      }
    });
    return;
  }

  reject(
    @"TypeError",
    [NSString stringWithFormat:@"No monero C++ method %@", method],
    nil
  );
}

- (NSDictionary *)constantsToExport
{
  NSMutableArray *out = [NSMutableArray arrayWithCapacity:moneroMethodCount];
  for (int i = 0; i < moneroMethodCount; ++i) {
    NSString *name = [NSString stringWithCString:moneroMethods[i].name
      encoding:NSUTF8StringEncoding];
    out[i] = name;
  }

  NSFileManager *fileManager = [NSFileManager defaultManager];
  NSURL *docsDir = [fileManager URLForDirectory:NSDocumentDirectory
    inDomain:NSUserDomainMask
    appropriateForURL:nil
    create:YES
    error:nil];
  NSString *docsPath = [docsDir path];

  return @{
    @"methodNames": out,
    @"documentDirectory": docsPath
  };
}

@end
