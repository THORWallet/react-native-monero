#ifndef MONERO_METHODS_HPP_INCLUDED
#define MONERO_METHODS_HPP_INCLUDED

#include <string>
#include <vector>
#include <functional>
#include <mutex>

struct MoneroMethod {
  const char *name;
  int argc;
  std::string (*method)(const std::vector<std::string> &args);
};
extern const MoneroMethod moneroMethods[];
extern const unsigned moneroMethodCount;

// Callback type for wallet events (walletId, eventName, jsonPayload)
using WalletEventCallback = std::function<void(
  const std::string&, const std::string&, const std::string&)>;

// Set the global callback invoked by WalletListener on the SDK refresh thread.
// Thread-safe: the callback is guarded by a mutex.
void moneroSetEventCallback(WalletEventCallback cb);

// Callback type for "the files of this wallet were just written" (walletId).
using WalletFilesChangedCallback = std::function<void(const std::string&)>;

// Set the global callback invoked after an open, close, or store has written
// the wallet files. iOS uses it to re-apply the iCloud backup exclusion, which
// wallet2's write-then-rename store drops. Thread-safe, and fires on the SDK
// refresh thread for the periodic stores during sync.
void moneroSetWalletFilesChangedCallback(WalletFilesChangedCallback cb);

#endif
