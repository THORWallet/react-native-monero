#include <stdio.h>
#include <string>
#include <stdexcept>
#include <map>
#include <memory>
#include <set>
#include <algorithm>
#include <vector>
#include <sstream>
#include <limits>
#include <ctime>
#include <atomic>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include "monero-methods.hpp"
#include "nym-fetch.hpp"
#include "ca-bundle.hpp"
#include "net/http_client.h"
#include "net/parse.h"
#include "net/socks_connect.h"
#include "wallet/api/wallet2_api.h"
#include "lws_frontend.h"

/** Lower-level utilities for key generation without disk I/O. */
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "mnemonics/electrum-words.h"
#include "string_tools.h"

/** Forward declaration for LWSF api_key support (defined in patched rpc.cpp). */
namespace lwsf { namespace config {
  void set_api_key(const std::string& k);
}}

/** Escapes a string for safe embedding in JSON (defined below). */
static std::string jsonEscape(const std::string& s);

/** Global wallet-event callback (thread-safe). */
static std::mutex g_eventCbMutex;
static WalletEventCallback g_walletEventCallback;

/** Global wallet-files-written callback (thread-safe). */
static std::mutex g_filesCbMutex;
static WalletFilesChangedCallback g_walletFilesChangedCallback;

void moneroSetWalletFilesChangedCallback(WalletFilesChangedCallback cb) {
  std::lock_guard<std::mutex> lock(g_filesCbMutex);
  g_walletFilesChangedCallback = cb;
}

static void notifyWalletFilesChanged(const std::string& walletId) {
  std::lock_guard<std::mutex> lock(g_filesCbMutex);
  if (!g_walletFilesChangedCallback) return;
  // Bookkeeping only: a platform failure here must not abort a store on the
  // refresh thread or fail an otherwise-successful open.
  try {
    g_walletFilesChangedCallback(walletId);
  } catch (...) {
  }
}

void moneroSetEventCallback(WalletEventCallback cb) {
  {
    std::lock_guard<std::mutex> lock(g_eventCbMutex);
    g_walletEventCallback = cb;
  }

  // Route nym fetch-request notifications through the same event pipeline
  // used by wallet listeners. We reuse the "walletId" slot for the request
  // id and pass the request payload as JSON data.
  nymfetch::setFetchRequestCallback(
    [](const std::string& requestId,
       const std::string& url,
       const std::string& method,
       const std::string& headersJson,
       const std::string& bodyBase64) {
      std::ostringstream payload;
      auto escape = [](const std::string& in) {
        std::string out;
        out.reserve(in.size() + 8);
        for (char c : in) {
          switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
              if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
              } else {
                out += c;
              }
          }
        }
        return out;
      };
      payload << "{\"url\":\"" << escape(url)
              << "\",\"method\":\"" << escape(method)
              << "\",\"headers\":" << (headersJson.empty() ? std::string("{}") : headersJson)
              << ",\"bodyBase64\":\"" << escape(bodyBase64) << "\"}";

      std::lock_guard<std::mutex> lock(g_eventCbMutex);
      if (g_walletEventCallback) {
        g_walletEventCallback(requestId, "nymFetchRequest", payload.str());
      }
    });
}

static void emitWalletEvent(const std::string& walletId,
                            const std::string& eventName,
                            const std::string& jsonPayload) {
  std::lock_guard<std::mutex> lock(g_eventCbMutex);
  if (g_walletEventCallback) {
    g_walletEventCallback(walletId, eventName, jsonPayload);
  }
}

std::string hello(const std::vector<std::string> &args) {
  printf("LWSF says hello\n");
  return "hello";
}

/** WalletListener implementation - handles wallet events and auto-saves during sync. */
class WalletListeners : public Monero::WalletListener {
public:
  WalletListeners(Monero::Wallet* wallet, const std::string& walletId)
    : m_wallet(wallet), m_walletId(walletId), m_lastSaveHeight(0) {}
  virtual ~WalletListeners() {}
  
  void moneySpent(const std::string &txId, uint64_t amount) override {}

  void moneyReceived(const std::string &txId, uint64_t amount) override {}

  void unconfirmedMoneyReceived(const std::string &txId, uint64_t amount) override {
    emitWalletEvent(m_walletId, "pendingTransactionReceived",
      "{\"txId\":\"" + txId + "\",\"amount\":" + std::to_string(amount) + "}");
  }
  
  void newBlock(uint64_t height) override {
    // Save progress every 1000 blocks during INITIAL sync only.
    // Once synchronized(), refreshed() takes over save responsibility.
    // This is safe because newBlock() is called from the refresh thread.
    const uint64_t SAVE_INTERVAL_BLOCKS = 1000;
    
    // Only save during initial sync (before wallet is fully synchronized)
    if (m_wallet->synchronized()) {
      return; // Let refreshed() handle saves once fully synced
    }
    
    if (height >= m_lastSaveHeight + SAVE_INTERVAL_BLOCKS) {
      try {
        m_wallet->store("");
        m_lastSaveHeight = height;
        notifyWalletFilesChanged(m_walletId);
      } catch (...) {
        // Ignore store errors during sync - will retry on next interval
      }
    }
  }
  
  void updated() override {}

  void refreshed() override {
    // A refresh cycle has completed: the backend has contacted the server and
    // merged the transaction history AND unspent outputs (for LWS, the refresh
    // fetches get_address_txs + get_unspent_outs before this fires), so the
    // wallet now knows its real balance and spendable outputs. Latch this so
    // getWalletStatus can report a genuine synced/spendable state rather than
    // the seed value LWS reports before its first refresh.
    m_hasRefreshed.store(true);

    // Called when refresh cycle completes - safe to store here
    try {
      m_wallet->store("");
      m_lastSaveHeight = m_wallet->blockChainHeight();
      notifyWalletFilesChanged(m_walletId);
    } catch (...) {
      // Ignore store errors - will retry on next refresh
    }
  }

  /** True once at least one server refresh has completed for this wallet. */
  bool hasRefreshed() const { return m_hasRefreshed.load(); }

private:
  Monero::Wallet* m_wallet;
  std::string m_walletId;
  uint64_t m_lastSaveHeight;
  std::atomic<bool> m_hasRefreshed{false};
};

/** Wallet tracking structure. */
struct WalletEntry {
  Monero::Wallet* wallet;
  std::unique_ptr<WalletListeners> listener;
  std::string backend;
  std::string path;
  std::string walletId;
  std::string connectionKey;
  
  uint64_t cachedSyncedHeight = 0;
  uint64_t cachedBalance = 0;
  uint64_t cachedUnlockedBalance = 0;
};

/**
 * Global state - stores all open wallets by ID.
 *
 * Thread-safety: g_wallets is only ever accessed from the serial bridge queue
 * (iOS DISPATCH_QUEUE_SERIAL, Android single-thread executor), so map reads and
 * writes are never concurrent. The refresh-thread WalletListener uses its own
 * wallet pointer and never touches this map, and closeWallet stops the wallet
 * (joining its refresh thread) before erasing the entry. Do not access
 * g_wallets from any other thread without adding synchronization.
 */
static std::map<std::string, WalletEntry> g_wallets;

/** A signed-but-not-yet-broadcast transaction and the wallet that owns it. */
struct RetainedTx {
  std::string walletId;
  Monero::PendingTransaction* ptx;
  uint64_t seq; // Insertion order, for FIFO eviction.
};

/**
 * Signed transactions awaiting broadcast, keyed by the signedTx hex returned to
 * JS from createTransaction.
 *
 * Edge signs a transaction in createTransaction and broadcasts it later in a
 * separate broadcastTransaction call (after the user confirms). We retain the
 * fully-signed PendingTransaction here and broadcast it directly, instead of
 * serializing it to a file and reloading it in broadcastTransaction. The file
 * round-trip is fundamentally broken on the full-node (wallet2) backend: its
 * save_tx writes an *unsigned* tx set while submitTransaction's load_tx expects
 * a *signed* one, so the magic prefixes never match and every full-node send
 * fails with "Failed to load transaction from file". Broadcasting the retained
 * PendingTransaction with commit("") works on both the LWS and full-node
 * backends. Every createTransaction retains, including fee-estimation calls
 * (getMaxSpendable) that never broadcast. Entries are disposed on broadcast,
 * when the owning wallet is closed/deleted, or oldest-first once a wallet
 * reaches MAX_RETAINED_TXS_PER_WALLET.
 *
 * Thread-safety: same serial-bridge-queue guarantee as g_wallets.
 */
static std::map<std::string, RetainedTx> g_retainedTxs;

/** Monotonic counter stamping g_retainedTxs insertion order. */
static uint64_t g_retainedTxSeq = 0;

/**
 * Cap on retained transactions per wallet. Several can be legitimately live at
 * once (swap quoting fans out one makeSpend per partner before the user picks a
 * quote), and abandoned ones (expired quotes, cancelled sends, fee
 * estimations) linger until the wallet closes, so a long session with quote
 * refreshes could otherwise grow without bound. Beyond the cap the oldest
 * entry is disposed first; a caller broadcasting an evicted tx gets the
 * explicit "recreate" error.
 */
static const size_t MAX_RETAINED_TXS_PER_WALLET = 50;

/** Retain a signed tx for later broadcast, evicting oldest-first at the cap. */
static void retainTx(const std::string& walletId, Monero::Wallet* wallet,
                     const std::string& signedTxHex, Monero::PendingTransaction* ptx) {
  size_t count = 0;
  auto oldest = g_retainedTxs.end();
  for (auto it = g_retainedTxs.begin(); it != g_retainedTxs.end(); ++it) {
    if (it->second.walletId != walletId) continue;
    ++count;
    if (oldest == g_retainedTxs.end() || it->second.seq < oldest->second.seq) {
      oldest = it;
    }
  }
  if (count >= MAX_RETAINED_TXS_PER_WALLET) {
    wallet->disposeTransaction(oldest->second.ptx);
    g_retainedTxs.erase(oldest);
  }
  g_retainedTxs[signedTxHex] = RetainedTx{ walletId, ptx, ++g_retainedTxSeq };
}

/** Dispose and forget any retained transactions owned by the given wallet. */
static void disposeRetainedTxs(const std::string& walletId, Monero::Wallet* wallet) {
  for (auto it = g_retainedTxs.begin(); it != g_retainedTxs.end();) {
    if (it->second.walletId == walletId) {
      wallet->disposeTransaction(it->second.ptx);
      it = g_retainedTxs.erase(it);
    } else {
      ++it;
    }
  }
}

/** Helper to get wallet manager based on backend type. */
static Monero::WalletManager* getWalletManager(const std::string& backend) {
  if (backend == "lws") {
    return lwsf::WalletManagerFactory::getWalletManager();
  } else {
    return Monero::WalletManagerFactory::getWalletManager();
  }
}

/**
 * Closes and untracks one wallet. The entry is always removed, even when the
 * backend reports a failed close, so a wallet can never become unclosable.
 */
static void closeWalletEntry(
    const std::map<std::string, WalletEntry>::iterator& it) {
  WalletEntry& entry = it->second;
  entry.wallet->setListener(nullptr);
  disposeRetainedTxs(entry.walletId, entry.wallet);
  Monero::WalletManager* manager = getWalletManager(entry.backend);
  const std::string walletId = entry.walletId;
  const bool closed = manager->closeWallet(entry.wallet);
  g_wallets.erase(it);
  // closeWallet stores by default, so the cache file on disk is a new one.
  notifyWalletFilesChanged(walletId);
  if (!closed) throw std::runtime_error("Failed to close wallet");
}

/**
 * Installs the bundled Mozilla roots before any OpenSSL-backed daemon client
 * is created. Mobile OpenSSL builds cannot read the platform trust store, so
 * verified TLS needs an explicit CA file. The file is app-private and is
 * rewritten once per process so package updates cannot retain stale roots.
 */
static std::string sha256Hex(const std::string& value) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), digest);
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (unsigned char byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

static std::string installBundledCa(const std::string& documentDirectory) {
  static std::mutex mutex;
  static std::string configuredDirectory;
  static std::string configuredPath;
  std::lock_guard<std::mutex> lock(mutex);
  if (configuredDirectory == documentDirectory) return configuredPath;
  if (documentDirectory.empty()) {
    throw std::runtime_error("Cannot configure TLS trust without a document directory");
  }

  const std::string path = documentDirectory + "/monero-ca-bundle.pem";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(kMoneroCaBundle, static_cast<std::streamsize>(kMoneroCaBundleSize));
  output.close();
  if (!output) {
    throw std::runtime_error("Failed to install Monero TLS CA bundle");
  }
  configuredDirectory = documentDirectory;
  configuredPath = path;
  return path;
}

static std::string installCertificatePem(
    const std::string& documentDirectory,
    const std::string& pem,
    const bool customCa) {
  static constexpr std::size_t MAX_CERTIFICATE_PEM_SIZE = 256 * 1024;
  if (pem.empty() || pem.size() > MAX_CERTIFICATE_PEM_SIZE) {
    throw std::runtime_error("TLS certificate PEM must be between 1 byte and 256 KiB");
  }
  const std::string begin = "-----BEGIN CERTIFICATE-----";
  const std::string end = "-----END CERTIFICATE-----";
  std::size_t endCount = 0;
  for (std::size_t endCursor = 0;
       (endCursor = pem.find(end, endCursor)) != std::string::npos;
       endCursor += end.size()) {
    ++endCount;
  }
  std::size_t cursor = 0;
  std::size_t certificateCount = 0;
  while (true) {
    const auto beginPos = pem.find(begin, cursor);
    if (beginPos == std::string::npos) break;
    const auto endPos = pem.find(end, beginPos + begin.size());
    if (endPos == std::string::npos) {
      throw std::runtime_error("TLS certificate PEM has an unterminated certificate");
    }
    const auto blockEnd = endPos + end.size();
    const std::string block = pem.substr(beginPos, blockEnd - beginPos);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(block.data(), static_cast<int>(block.size())), &BIO_free);
    if (!bio) throw std::runtime_error("Failed to parse TLS certificate PEM");
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free);
    if (!certificate) {
      throw std::runtime_error("TLS certificate PEM contains an invalid certificate");
    }
    if (customCa && X509_check_ca(certificate.get()) <= 0) {
      throw std::runtime_error("TLS custom CA PEM contains a non-CA certificate");
    }
    // Reject only an explicit `basicConstraints: CA:TRUE`. Monerod's generated
    // certificate is a self-signed V1 leaf, which X509_check_ca also reports as
    // CA-capable, and pinning it is the main use of this mode.
    if (!customCa && X509_check_ca(certificate.get()) == 1) {
      throw std::runtime_error(
          "TLS certificate mode requires a peer certificate, not a CA");
    }
    ++certificateCount;
    cursor = blockEnd;
  }
  if (certificateCount == 0 || certificateCount != endCount ||
      (!customCa && certificateCount != 1)) {
    throw std::runtime_error(
        customCa
            ? "TLS custom CA mode requires one or more PEM CA certificates"
            : "TLS certificate mode requires exactly one PEM certificate");
  }
  if (documentDirectory.empty()) {
    throw std::runtime_error("Cannot install TLS certificate without a document directory");
  }
  const std::string path =
      documentDirectory + (customCa ? "/monero-custom-ca-" : "/monero-peer-") +
      sha256Hex(pem) + ".pem";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(pem.data(), static_cast<std::streamsize>(pem.size()));
  output.close();
  if (!output) throw std::runtime_error("Failed to install TLS certificate PEM");
  return path;
}

static std::string lowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

static bool isOnionHost(const std::string& host) {
  const std::string lower = lowerAscii(host);
  return lower.size() > 6 &&
      lower.compare(lower.size() - 6, 6, ".onion") == 0;
}

static std::vector<std::uint8_t> parseFingerprint(const std::string& input) {
  std::string hex;
  hex.reserve(input.size());
  for (char c : input) {
    if (c == ':') continue;
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      throw std::runtime_error("TLS fingerprint must be hexadecimal SHA-256");
    }
    hex.push_back(c);
  }
  if (hex.size() != SSL_FINGERPRINT_SIZE * 2) {
    throw std::runtime_error("TLS fingerprint must contain exactly 32 bytes");
  }
  std::vector<std::uint8_t> bytes;
  bytes.reserve(SSL_FINGERPRINT_SIZE);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    bytes.push_back(static_cast<std::uint8_t>(
        std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return bytes;
}

struct DaemonConnection {
  std::string address;
  std::string proxyAddress;
  std::string key;
  epee::net_utils::ssl_options_t sslOptions;

  DaemonConnection()
      : sslOptions(epee::net_utils::ssl_support_t::e_ssl_support_disabled) {}
};

static DaemonConnection makeDaemonConnection(
    const std::string& documentDirectory,
    std::string address,
    std::string mode,
    const std::string& value,
    std::string proxyAddress) {
  epee::net_utils::http::url_content url{};
  if (!epee::net_utils::parse_url(address, url)) {
    throw std::runtime_error("Invalid daemon URL");
  }
  const std::string scheme = lowerAscii(url.schema);
  const bool https = scheme == "https";
  if (!https && scheme != "http") {
    throw std::runtime_error("Daemon URL must use http or https");
  }
  const bool externalTransport = nymfetch::isEnabled();
  const bool onion = isOnionHost(url.host);
  mode = lowerAscii(mode);
  if (mode.empty()) {
    mode = externalTransport ? "external" : (https ? "bundled-ca" : "disabled");
  }

  if (externalTransport && mode != "external") {
    throw std::runtime_error(
        "Nym transport requires TLS external mode; native TLS policies "
        "cannot be enforced by the JS transport");
  }
  if (!externalTransport && mode == "external") {
    throw std::runtime_error(
        "TLS external mode requires the Nym fetch transport");
  }
  if (!externalTransport && onion && mode != "onion") {
    throw std::runtime_error("A .onion daemon requires TLS onion mode");
  }
  if (!externalTransport && mode == "onion" && !onion) {
    throw std::runtime_error("TLS onion mode is only valid for .onion hosts");
  }
  if (!externalTransport && mode == "onion" && proxyAddress.empty()) {
    throw std::runtime_error("A .onion daemon requires a SOCKS proxy address");
  }
  if (!https && mode != "disabled" && mode != "onion" &&
      mode != "external") {
    throw std::runtime_error("TLS verification modes require an https daemon");
  }

  DaemonConnection out;
  out.address = std::move(address);
  out.proxyAddress = std::move(proxyAddress);
  if (mode == "disabled") {
    out.sslOptions =
        epee::net_utils::ssl_support_t::e_ssl_support_disabled;
  } else if (mode == "bundled-ca") {
    out.sslOptions =
        epee::net_utils::ssl_support_t::e_ssl_support_enabled;
    out.sslOptions.ca_path = installBundledCa(documentDirectory);
  } else if (mode == "fingerprint") {
    out.sslOptions = epee::net_utils::ssl_options_t{
        {parseFingerprint(value)}, ""};
  } else if (mode == "certificate") {
    out.sslOptions = epee::net_utils::ssl_options_t{
        {}, installCertificatePem(documentDirectory, value, false)};
  } else if (mode == "custom-ca") {
    out.sslOptions = epee::net_utils::ssl_options_t{
        {}, installCertificatePem(documentDirectory, value, true)};
    out.sslOptions.verification =
        epee::net_utils::ssl_verification_t::user_ca;
  } else if (mode == "unverified" || mode == "onion") {
    out.sslOptions = https
        ? epee::net_utils::ssl_options_t{
              epee::net_utils::ssl_support_t::e_ssl_support_enabled}
        : epee::net_utils::ssl_options_t{
              epee::net_utils::ssl_support_t::e_ssl_support_disabled};
    out.sslOptions.verification = epee::net_utils::ssl_verification_t::none;
  } else if (mode == "external") {
    out.sslOptions = https
        ? epee::net_utils::ssl_options_t{
              epee::net_utils::ssl_support_t::e_ssl_support_enabled}
        : epee::net_utils::ssl_options_t{
              epee::net_utils::ssl_support_t::e_ssl_support_disabled};
    out.sslOptions.verification = epee::net_utils::ssl_verification_t::none;
  } else {
    throw std::runtime_error("Unsupported TLS mode: " + mode);
  }
  out.key = out.address + "\n" + mode + "\n" + sha256Hex(value) +
      "\n" + out.proxyAddress;
  return out;
}

/**
 * Validates that a walletId is safe to embed in a filesystem path. Wallet ids
 * are base64url strings, so we only allow [A-Za-z0-9_-]; anything else (e.g. a
 * '/', '.', or '\\') is rejected to prevent path traversal / unintended file
 * locations.
 */
static void requireSafeWalletId(const std::string& walletId) {
  if (walletId.empty()) {
    throw std::runtime_error("Invalid walletId: empty");
  }
  for (char c : walletId) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) {
      throw std::runtime_error("Invalid walletId: unsafe character");
    }
  }
}

/** Helper to find wallet by ID or throw exception. */
static WalletEntry& findWalletOrThrow(const std::string& walletId) {
  auto it = g_wallets.find(walletId);
  if (it == g_wallets.end()) {
    throw std::runtime_error("Wallet not found");
  }
  return it->second;
}

/** Helper to find any open wallet matching the given nettype. */
static Monero::Wallet* findWalletByNettype(int nettype) {
  Monero::NetworkType network = static_cast<Monero::NetworkType>(nettype);
  for (const auto& pair : g_wallets) {
    if (pair.second.wallet->nettype() == network) {
      return pair.second.wallet;
    }
  }
  throw std::runtime_error("No open wallet found for the requested network type");
}

/**
 * Generate a new wallet's keys in memory (no disk I/O).
 * Args: nettype, language
 * Returns: JSON with mnemonic, secretSpendKey, publicSpendKey
 */
std::string generateWallet(const std::vector<std::string> &args) {
  int nettype = std::stoi(args[0]);
  std::string language = args[1];
  
  // Generate keys in memory using account_base (no disk persistence)
  cryptonote::account_base account;
  account.generate();
  
  const auto& keys = account.get_keys();
  
  // Convert spend secret key to mnemonic
  epee::wipeable_string mnemonic;
  if (!crypto::ElectrumWords::bytes_to_words(keys.m_spend_secret_key, mnemonic, language)) {
    throw std::runtime_error("Failed to convert keys to mnemonic");
  }
  
  // Convert keys to hex strings (secret keys need unwrap() to get underlying POD)
  std::string secret_spend_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_spend_secret_key)));
  std::string public_spend_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_spend_public_key);
  
  // Build JSON response
  std::string json = "{";
  json += "\"mnemonic\":\"" + std::string(mnemonic.data(), mnemonic.size()) + "\",";
  json += "\"secretSpendKey\":\"" + secret_spend_key + "\",";
  json += "\"publicSpendKey\":\"" + public_spend_key + "\"";
  json += "}";
  
  return json;
}

/**
 * Derive all keys from a mnemonic (no disk I/O).
 * Args: mnemonic, nettype
 * Returns: JSON with address, secretViewKey, publicViewKey, secretSpendKey, publicSpendKey
 */
std::string seedAndKeysFromMnemonic(const std::vector<std::string> &args) {
  std::string mnemonic_str = args[0];
  int nettype = std::stoi(args[1]);
  
  // Convert mnemonic to spend secret key
  crypto::secret_key spend_secret;
  std::string language_name;
  epee::wipeable_string mnemonic_ws(mnemonic_str);
  
  if (!crypto::ElectrumWords::words_to_bytes(mnemonic_ws, spend_secret, language_name)) {
    throw std::runtime_error("Invalid mnemonic");
  }
  
  // Recover account from spend key (derives view key automatically)
  cryptonote::account_base account;
  account.generate(spend_secret, true, false);  // recover=true
  
  const auto& keys = account.get_keys();
  
  // Get address string
  cryptonote::network_type network = static_cast<cryptonote::network_type>(nettype);
  std::string address = account.get_public_address_str(network);
  
  // Convert keys to hex strings (secret keys need unwrap() to get underlying POD)
  std::string secret_view_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_view_secret_key)));
  std::string public_view_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_view_public_key);
  std::string secret_spend_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_spend_secret_key)));
  std::string public_spend_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_spend_public_key);
  
  // Build JSON response
  std::string json = "{";
  json += "\"address\":\"" + address + "\",";
  json += "\"secretViewKey\":\"" + secret_view_key + "\",";
  json += "\"publicViewKey\":\"" + public_view_key + "\",";
  json += "\"secretSpendKey\":\"" + secret_spend_key + "\",";
  json += "\"publicSpendKey\":\"" + public_spend_key + "\"";
  json += "}";
  
  return json;
}

/**
 * Get network blockchain height from daemon.
 * Args: documentDirectory, backend, nettype, daemonAddress, tlsMode,
 *       tlsValue, proxyAddress
 * Returns: blockchain height as string
 */
std::string getNetworkBlockHeight(const std::vector<std::string> &args) {
  std::string documentDirectory = args[0];
  std::string backend = args[1];
  int nettype = std::stoi(args[2]);
  (void)nettype;
  DaemonConnection connection = makeDaemonConnection(
      documentDirectory, args[3], args[4], args[5], args[6]);
  if (nymfetch::isEnabled() && backend != "lws") {
    throw std::runtime_error(
        "Monerod network-height probes are unavailable through Nym");
  }
  
  // The WalletManager is a shared singleton, but its daemon address is only
  // read by this method, which re-sets it on every call before querying. Wallet
  // operations connect via their own wallet->init(), not the manager's address,
  // so this transient mutation cannot perturb other wallets/sessions.
  Monero::WalletManager* manager = getWalletManager(backend);
  manager->setDaemonAddressWithTls(
      connection.address, connection.sslOptions, connection.proxyAddress);
  
  // Check if connected
  if (!manager->connected()) {
    throw std::runtime_error(
        "Failed to connect to daemon at " + connection.address);
  }
  
  uint64_t height = manager->blockchainHeight();
  return std::to_string(height);
}

/**
 * Perform only a direct TLS handshake and return the peer leaf SHA-256
 * fingerprint. This deliberately uses verification=none for TOFU discovery;
 * callers must confirm and persist the returned fingerprint before use.
 * Args: daemonAddress, proxyAddress
 */
std::string discoverTlsPeerIdentity(const std::vector<std::string> &args) {
  epee::net_utils::http::url_content url{};
  if (!epee::net_utils::parse_url(args[0], url) ||
      lowerAscii(url.schema) != "https") {
    throw std::runtime_error(
        "TLS peer identity discovery requires an https daemon URL");
  }
  const bool onion = isOnionHost(url.host);
  const std::string proxyAddress = args[1];
  if (onion && proxyAddress.empty()) {
    throw std::runtime_error("A .onion daemon requires a SOCKS proxy address");
  }

  std::string fingerprint;
  epee::net_utils::ssl_options_t options{
      epee::net_utils::ssl_support_t::e_ssl_support_enabled};
  options.verification = epee::net_utils::ssl_verification_t::none;
  options.peer_fingerprint_callback =
      [&fingerprint](const std::string& value) { fingerprint = value; };

  epee::net_utils::http::http_simple_client client;
  if (!proxyAddress.empty()) {
    auto endpoint = net::get_tcp_endpoint(proxyAddress);
    if (!endpoint) throw std::runtime_error("Invalid SOCKS proxy address");
    client.set_connector(net::socks::connector{std::move(*endpoint)});
  }
  const std::uint64_t port = url.port == 0 ? 443 : url.port;
  client.set_server(
      std::move(url.host), std::to_string(port), boost::none,
      std::move(options));
  if (!client.connect(std::chrono::seconds(15)) || fingerprint.empty()) {
    throw std::runtime_error("Failed to discover TLS peer identity");
  }
  client.disconnect();
  return "{\"sha256Fingerprint\":\"" + jsonEscape(fingerprint) + "\"}";
}

/**
 * Validate a Monero address.
 * Args: address, nettype
 * Returns: "true" or "false"
 */
std::string isValidAddress(const std::vector<std::string> &args) {
  std::string address = args[0];
  int nettype = std::stoi(args[1]);
  Monero::NetworkType network = static_cast<Monero::NetworkType>(nettype);

  // addressValid is a static method on Monero::Wallet
  bool valid = Monero::Wallet::addressValid(address, network);
  return valid ? "true" : "false";
}

/**
 * JSON fields carrying the wallet's last backend error. A rejected TLS
 * handshake or an unreachable daemon makes the SDK skip its refresh, which is
 * otherwise invisible to the caller: it only sees `refreshed` staying false
 * until its own stall timeout expires. Reported on every status-shaped
 * response so a poll loop can fail fast instead of waiting that out.
 */
static std::string walletStatusFields(Monero::Wallet* wallet) {
  int status = Monero::Wallet::Status_Ok;
  std::string error;
  // Read both under the SDK's status lock: the refresh thread can overwrite
  // them between two separate status()/errorString() calls.
  wallet->statusWithErrorString(status, error);
  if (status == Monero::Wallet::Status_Ok) error.clear();
  return "\"status\":" + std::to_string(status) + "," +
      "\"errorString\":\"" + jsonEscape(error) + "\"";
}

/**
 * Open or create a wallet.
 * Args: documentDirectory, walletId, backend, mnemonic, password, nettype,
 *       restoreHeight, daemonAddress, tlsMode, tlsValue, proxyAddress
 * Returns: JSON with syncedHeight, networkHeight, balance, and unlockedBalance
 */
std::string openWallet(const std::vector<std::string> &args) {
  std::string documentDirectory = args[0];
  std::string walletId = args[1];
  std::string backend = args[2];
  std::string mnemonic = args[3];
  std::string password = args[4];
  int nettype = std::stoi(args[5]);
  uint64_t restoreHeight = std::stoull(args[6]);
  DaemonConnection connection = makeDaemonConnection(
      documentDirectory, args[7], args[8], args[9], args[10]);

  Monero::NetworkType network = static_cast<Monero::NetworkType>(nettype);

  // Check if wallet is already open
  auto it = g_wallets.find(walletId);
  if (it != g_wallets.end()) {
    WalletEntry& entry = it->second;
    // A different backend or network is a different wallet, so refuse it
    // instead of discarding the open one's retained transactions for an open
    // that cannot succeed against the same wallet file.
    if (entry.backend != backend || entry.wallet->nettype() != network) {
      throw std::runtime_error(
          "Wallet is already open with a different backend or network");
    }
    if (entry.connectionKey == connection.key) {
      Monero::Wallet* wallet = entry.wallet;
      wallet->startRefresh();

      uint64_t syncedHeight = wallet->blockChainHeight();
      uint64_t networkHeight = wallet->daemonBlockChainHeight();
      uint64_t balance = wallet->balanceAll();
      uint64_t unlockedBalance = wallet->unlockedBalanceAll();

      entry.cachedSyncedHeight = syncedHeight;
      entry.cachedBalance = balance;
      entry.cachedUnlockedBalance = unlockedBalance;

      std::string json = "{";
      json += "\"syncedHeight\":" + std::to_string(syncedHeight) + ",";
      json += "\"networkHeight\":" + std::to_string(networkHeight) + ",";
      json += "\"balance\":\"" + std::to_string(balance) + "\",";
      json += "\"unlockedBalance\":\"" + std::to_string(unlockedBalance) + "\",";
      json += "\"refreshed\":" +
          std::string(entry.listener->hasRefreshed() ? "true" : "false") + ",";
      json += walletStatusFields(wallet);
      json += "}";
      return json;
    }
    // A repeated open with new transport settings is an explicit
    // reconfiguration request. Close first so failed TLS settings do not latch.
    closeWalletEntry(it);
  }

  Monero::WalletManager* manager = getWalletManager(backend);
  
  requireSafeWalletId(walletId);
  std::string path = documentDirectory + "/" + backend + "_" + walletId;
  
  Monero::Wallet* wallet = nullptr;
  
  if (manager->walletExists(path)) {
    wallet = manager->openWallet(path, password, network);
    wallet->setRecoveringFromSeed(true);
  } else {
    wallet = manager->recoveryWallet(path, password, mnemonic, network, restoreHeight);
  }
  
  if (wallet == nullptr) {
    throw std::runtime_error("Failed to open or create wallet");
  }
  
  if (wallet->status() != Monero::Wallet::Status_Ok) {
    std::string error = wallet->errorString();
    manager->closeWallet(wallet, false);
    throw std::runtime_error("Wallet error: " + error);
  }
  
  const bool isLws = (backend == "lws");
  try {
    if (!wallet->initWithTls(
            connection.address, 0, "", "", isLws, connection.proxyAddress,
            connection.sslOptions)) {
      const std::string error = wallet->errorString();
      throw std::runtime_error(
          "Failed to initialize wallet daemon connection" +
          (error.empty() ? std::string() : ": " + error));
    }
  } catch (...) {
    try {
      manager->closeWallet(wallet, false);
    } catch (...) {
      // Preserve the initialization error.
    }
    throw;
  }

  auto listener = std::make_unique<WalletListeners>(wallet, walletId);
  wallet->setListener(listener.get());

  wallet->startRefresh();
  
  uint64_t syncedHeight = wallet->blockChainHeight();
  uint64_t networkHeight = wallet->daemonBlockChainHeight();
  uint64_t balance = wallet->balanceAll();
  uint64_t unlockedBalance = wallet->unlockedBalanceAll();
  
  WalletEntry entry;
  entry.wallet = wallet;
  entry.listener = std::move(listener);
  entry.backend = backend;
  entry.path = path;
  entry.walletId = walletId;
  entry.connectionKey = connection.key;
  entry.cachedSyncedHeight = syncedHeight;
  entry.cachedBalance = balance;
  entry.cachedUnlockedBalance = unlockedBalance;
  g_wallets[walletId] = std::move(entry);
  notifyWalletFilesChanged(walletId);

  std::string json = "{";
  json += "\"syncedHeight\":" + std::to_string(syncedHeight) + ",";
  json += "\"networkHeight\":" + std::to_string(networkHeight) + ",";
  json += "\"balance\":\"" + std::to_string(balance) + "\",";
  json += "\"unlockedBalance\":\"" + std::to_string(unlockedBalance) + "\",";
  json += "\"refreshed\":false,";
  json += walletStatusFields(wallet);
  json += "}";

  return json;
}

/**
 * Get wallet status (synced and network heights, balances).
 * Args: walletId
 * Returns: JSON with syncedHeight, networkHeight, balance, and unlockedBalance
 */
std::string getWalletStatus(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  WalletEntry& entry = findWalletOrThrow(walletId);
  Monero::Wallet* wallet = entry.wallet;
  
  uint64_t syncedHeight = wallet->blockChainHeight();
  uint64_t networkHeight = wallet->daemonBlockChainHeight();

  // Always read the live balance. A pending incoming transaction, or the
  // pending change after a send, does not advance blockChainHeight, so gating
  // the recompute on a height change left the reported balance stale (showing
  // a just-received pending amount as 0) until the next block arrived.
  // balanceAll()/unlockedBalanceAll() read wallet2's in-memory transfer state
  // and are inexpensive relative to the sync poll cadence.
  uint64_t balance = wallet->balanceAll();
  uint64_t unlockedBalance = wallet->unlockedBalanceAll();

  entry.cachedSyncedHeight = syncedHeight;
  entry.cachedBalance = balance;
  entry.cachedUnlockedBalance = unlockedBalance;

  // syncedHeight/networkHeight are seeded equal on an LWS wallet until its
  // first server refresh, so heights alone cannot distinguish "caught up" from
  // "has not looked yet". Report whether a real refresh has completed so the
  // caller only treats the wallet as synced (and spendable) once it has.
  bool refreshed = entry.listener != nullptr && entry.listener->hasRefreshed();

  std::string json = "{";
  json += "\"syncedHeight\":" + std::to_string(syncedHeight) + ",";
  json += "\"networkHeight\":" + std::to_string(networkHeight) + ",";
  json += "\"balance\":\"" + std::to_string(balance) + "\",";
  json += "\"unlockedBalance\":\"" + std::to_string(unlockedBalance) + "\",";
  json += "\"refreshed\":" + std::string(refreshed ? "true" : "false") + ",";
  json += walletStatusFields(wallet);
  json += "}";

  return json;
}

/**
 * Close an open wallet.
 * Args: walletId
 * Returns: "ok"
 */
std::string closeWallet(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  auto it = g_wallets.find(walletId);
  if (it == g_wallets.end()) throw std::runtime_error("Wallet not found");
  closeWalletEntry(it);
  
  return "ok";
}

/**
 * Delete a wallet's files from disk. Closes the wallet first if it's open.
 * Args: documentDirectory, walletId, backend
 * Returns: "ok"
 */
std::string deleteWallet(const std::vector<std::string> &args) {
  std::string documentDirectory = args[0];
  std::string walletId = args[1];
  std::string backend = args[2];

  auto it = g_wallets.find(walletId);
  if (it != g_wallets.end()) {
    closeWalletEntry(it);
  }

  requireSafeWalletId(walletId);
  std::string path = documentDirectory + "/" + backend + "_" + walletId;
  std::remove((path).c_str());
  std::remove((path + ".keys").c_str());
  std::remove((path + ".address.txt").c_str());

  return "ok";
}

/** Serialize one TransactionInfo to a JSON object (shared by the tx queries). */
static std::string transactionToJson(Monero::Wallet* wallet, Monero::TransactionInfo* tx) {
  // lwsf reports an unmined block height as uint64 max and an unknown
  // timestamp as time_t max/min. Those sentinels do not survive JSON number
  // parsing in JS (doubles lose integer precision past 2^53), so emit 0
  // instead; isPending/isFailed carry the state.
  uint64_t blockHeight = tx->blockHeight();
  if (blockHeight == std::numeric_limits<uint64_t>::max()) blockHeight = 0;
  std::time_t timestamp = tx->timestamp();
  if (timestamp == std::numeric_limits<std::time_t>::max() ||
      timestamp == std::numeric_limits<std::time_t>::min()) {
    timestamp = 0;
  }

  std::string json = "{\"hash\":\"" + jsonEscape(tx->hash()) + "\",";
  json += "\"direction\":" + std::to_string(tx->direction()) + ",";
  json += "\"isPending\":" + std::string(tx->isPending() ? "true" : "false") + ",";
  json += "\"isFailed\":" + std::string(tx->isFailed() ? "true" : "false") + ",";
  json += "\"isCoinbase\":" + std::string(tx->isCoinbase() ? "true" : "false") + ",";
  json += "\"amount\":\"" + std::to_string(tx->amount()) + "\",";
  json += "\"fee\":\"" + std::to_string(tx->fee()) + "\",";
  json += "\"blockHeight\":" + std::to_string(blockHeight) + ",";
  json += "\"confirmations\":" + std::to_string(tx->confirmations()) + ",";
  json += "\"timestamp\":" + std::to_string(timestamp) + ",";
  json += "\"paymentId\":\"" + jsonEscape(tx->paymentId()) + "\",";
  json += "\"description\":\"" + jsonEscape(tx->description()) + "\",";
  json += "\"label\":\"" + jsonEscape(tx->label()) + "\",";
  json += "\"unlockTime\":" + std::to_string(tx->unlockTime()) + ",";
  json += "\"subaddrAccount\":" + std::to_string(tx->subaddrAccount()) + ",";
  // Incoming transfers carry a single minor index; outgoing can spend from
  // several. Expose the full set so callers can pick the right one.
  json += "\"subaddrIndex\":[";
  {
    bool first = true;
    for (uint32_t idx : tx->subaddrIndex()) {
      if (!first) json += ",";
      first = false;
      json += std::to_string(idx);
    }
  }
  json += "]";

  try {
    std::string txKey = wallet->getTxKey(tx->hash());
    if (!txKey.empty()) {
      json += ",\"txKey\":\"" + jsonEscape(txKey) + "\"";
    }
  } catch (...) {
  }

  json += "}";
  return json;
}

/**
 * Serialize one page of a transaction list to the paged JSON envelope shared
 * by the tx queries. Clamps the page window into [0, txs.size()]: JS-supplied
 * page/pageSize are not validated by the dispatchers, and a negative page
 * would otherwise index out of bounds (a native crash, not a catchable
 * rejection). The math is done in 64-bit so a huge page * pageSize cannot
 * overflow int.
 */
static std::string transactionsPageJson(
  Monero::Wallet* wallet,
  const std::vector<Monero::TransactionInfo*>& txs,
  int page,
  int pageSize
) {
  const long long total = static_cast<long long>(txs.size());
  long long start = static_cast<long long>(page) * pageSize;
  if (start < 0) start = 0;
  if (start > total) start = total;
  long long end = pageSize > 0 ? start + pageSize : start;
  if (end > total) end = total;

  std::string json = "{\"transactions\":[";
  for (long long i = start; i < end; i++) {
    if (i > start) json += ",";
    json += transactionToJson(wallet, txs[static_cast<size_t>(i)]);
  }
  json += "],\"totalCount\":" + std::to_string(total) + ",";
  json += "\"page\":" + std::to_string(page) + ",\"pageSize\":" + std::to_string(pageSize) + "}";

  return json;
}

/**
 * Get all transactions with pagination.
 * Args: walletId, page (0-indexed), pageSize, sort ("asc" or "desc")
 * Returns: JSON with transactions array, totalCount, page, pageSize
 */
std::string getAllTransactions(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  int page = std::stoi(args[1]);
  int pageSize = std::stoi(args[2]);
  bool ascending = (args[3] == "asc");
  
  Monero::Wallet* wallet = findWalletOrThrow(walletId).wallet;
  
  Monero::TransactionHistory* history = wallet->history();
  history->refresh();
  std::vector<Monero::TransactionInfo*> txs = history->getAll();
  
  std::sort(txs.begin(), txs.end(), [ascending](Monero::TransactionInfo* a, Monero::TransactionInfo* b) {
    if (a->isPending() != b->isPending()) return !a->isPending();
    return ascending ? a->blockHeight() < b->blockHeight() : a->blockHeight() > b->blockHeight();
  });

  return transactionsPageJson(wallet, txs, page, pageSize);
}

/**
 * Get not-yet-mined transactions with pagination. Same transaction shape as
 * getAllTransactions, filtered to isPending(), in history order. Pending
 * entries sort behind every confirmed transaction in getAllTransactions, so a
 * cursor-based scan over confirmed history never reaches them; this gives the
 * engine a direct view of the (small) pending set instead. Note the set can
 * include entries the backend reports as permanently failed (wallet2 keeps
 * failed sends flagged pending+failed); callers use isFailed to tell them
 * apart.
 * Args: walletId, page (0-indexed), pageSize
 * Returns: JSON with transactions array, totalCount, page, pageSize
 */
std::string getPendingTransactions(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  int page = std::stoi(args[1]);
  int pageSize = std::stoi(args[2]);

  Monero::Wallet* wallet = findWalletOrThrow(walletId).wallet;

  Monero::TransactionHistory* history = wallet->history();
  history->refresh();
  std::vector<Monero::TransactionInfo*> all = history->getAll();

  std::vector<Monero::TransactionInfo*> txs;
  for (Monero::TransactionInfo* tx : all) {
    if (tx->isPending()) txs.push_back(tx);
  }

  return transactionsPageJson(wallet, txs, page, pageSize);
}

/** Helper to split a comma-separated string. */
static std::vector<std::string> splitString(const std::string& str, char delimiter) {
  std::vector<std::string> tokens;
  std::stringstream ss(str);
  std::string token;
  while (std::getline(ss, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

/**
 * Create a transaction (multi-recipient supported).
 * Args: walletId, addresses (comma-separated), amounts (comma-separated), priority, documentDirectory (unused)
 * Returns: JSON with txid, signedTxHex, and fee
 */
std::string createTransaction(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  std::string addressesStr = args[1];
  std::string amountsStr = args[2];
  int priority = std::stoi(args[3]);
  // args[4] (documentDirectory) is kept for arg-count compatibility; unused.

  WalletEntry& entry = findWalletOrThrow(walletId);
  Monero::Wallet* wallet = entry.wallet;
  
  std::vector<std::string> addresses = splitString(addressesStr, ',');
  std::vector<std::string> amountStrs = splitString(amountsStr, ',');
  
  if (addresses.empty() || addresses.size() != amountStrs.size()) {
    throw std::runtime_error("Addresses and amounts must have same length and not be empty");
  }
  
  std::vector<uint64_t> amounts;
  for (const auto& amt : amountStrs) {
    amounts.push_back(std::stoull(amt));
  }

  Monero::optional<std::vector<uint64_t>> optAmounts;
  if (addresses.size() == 1 && amounts.size() == 1 && amounts[0] == 0) {
    optAmounts = std::nullopt;
  } else {
    optAmounts = amounts;
  }
  
  wallet->pauseRefresh();
  
  Monero::PendingTransaction* ptx = wallet->createTransactionMultDest(
    addresses,
    "",
    optAmounts,
    0,
    static_cast<Monero::PendingTransaction::Priority>(priority)
  );
  
  wallet->startRefresh();
  
  if (ptx == nullptr) {
    throw std::runtime_error("Failed to create transaction");
  }
  
  if (ptx->status() != Monero::PendingTransaction::Status_Ok) {
    std::string error = ptx->errorString();
    wallet->disposeTransaction(ptx);
    throw std::runtime_error("Transaction error: " + error);
  }
  
  std::vector<std::string> txIds = ptx->txid();

  // Reject payments the wallet split into multiple on-chain transactions.
  // commit("") broadcasts a multi-tx set sequentially with no rollback: a
  // mid-sequence failure would leave part of the funds moved on-chain while
  // this method reports total failure, and disposing the object would destroy
  // the still-unsent remainder. Requiring exactly one tx keeps
  // broadcastTransaction atomic (it either fully broadcast or it is safe to
  // recreate).
  if (txIds.size() != 1) {
    std::string count = std::to_string(txIds.size());
    wallet->disposeTransaction(ptx);
    throw std::runtime_error(
      "Transaction would split into " + count +
      " transactions; send a smaller amount");
  }
  std::string txHash = txIds[0];
  uint64_t fee = ptx->fee();

  // The txid doubles as the `signedTxHex` token returned to JS: it only
  // identifies the retained PendingTransaction in g_retainedTxs, and the
  // signed bytes never leave the native side (reloading serialized bytes to
  // broadcast is exactly the broken full-node path this design avoids), so
  // there is no reason to serialize, hex-encode, and ship them across the
  // bridge just to mint a lookup key.
  //
  // Keep the fully-signed transaction alive until broadcastTransaction.
  // Callers that never broadcast (fee estimation) leave the entry to FIFO
  // eviction or the wallet-close sweep.
  retainTx(walletId, wallet, txHash, ptx);

  return "{\"txid\":\"" + txHash + "\",\"signedTxHex\":\"" + txHash + "\",\"fee\":\"" + std::to_string(fee) + "\"}";
}

/**
 * Broadcast a previously created transaction. Broadcasts the retained
 * PendingTransaction that createTransaction kept alive, looked up by the
 * signedTxHex token; the signed bytes are never reloaded from the token.
 * Args: walletId, signedTxHex (from createTransaction), documentDirectory (unused)
 * Returns: "success"
 */
std::string broadcastTransaction(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  std::string signedTxHex = args[1];
  // args[2] (documentDirectory) is kept for arg-count compatibility; unused.

  WalletEntry& entry = findWalletOrThrow(walletId);
  Monero::Wallet* wallet = entry.wallet;

  auto it = g_retainedTxs.find(signedTxHex);
  if (it == g_retainedTxs.end()) {
    throw std::runtime_error("No pending transaction to broadcast; it may have expired. Please recreate the transaction.");
  }
  // The retained transaction spends from the wallet that created it; a
  // mismatched walletId is a caller bookkeeping bug. Refuse rather than
  // silently spending from the other wallet.
  if (it->second.walletId != walletId) {
    throw std::runtime_error("The pending transaction belongs to a different wallet");
  }

  Monero::PendingTransaction* ptx = it->second.ptx;

  // Broadcast the already-signed transaction directly. commit("") (empty
  // filename) commits to the network on both the LWS and full-node backends.
  // We deliberately do NOT reload the tx from the signed hex via
  // submitTransaction/load_tx: on the full-node wallet2 backend the saved blob
  // is an unsigned tx set that load_tx rejects, which is the historical
  // "Failed to load transaction from file" full-node send failure.
  bool success = ptx->commit("");
  std::string error = success ? std::string() : ptx->errorString();

  // Dispose on failure too. A retry of the same object is not reliable across
  // backends (lwsf poisons the object's status after a failed send, and
  // wallet2 never resets it), so the failure is terminal by design. This is
  // safe because createTransaction guarantees a single on-chain tx: nothing
  // can be partially broadcast, and a recreated transaction spends the same
  // inputs, so if the original did reach the network after a timeout the
  // recreated one is simply rejected as a double spend rather than moving
  // funds twice.
  wallet->disposeTransaction(ptx);
  g_retainedTxs.erase(it);

  if (!success) {
    throw std::runtime_error(
      "Broadcast failed: " + error +
      ". The transaction was discarded; create a new one to retry.");
  }

  return "success";
}

/** Helper: escape a string for JSON, including every control byte. */
static std::string jsonEscape(const std::string& s) {
  std::string result;
  result.reserve(s.size());
  static constexpr char hex[] = "0123456789abcdef";
  for (unsigned char c : s) {
    if (c == '\\') result += "\\\\";
    else if (c == '"') result += "\\\"";
    else if (c == '\n') result += "\\n";
    else if (c == '\r') result += "\\r";
    else if (c == '\t') result += "\\t";
    else if (c < 0x20) {
      result += "\\u00";
      result += hex[c >> 4];
      result += hex[c & 0x0f];
    } else {
      result += static_cast<char>(c);
    }
  }
  return result;
}

/**
 * Parse a monero: URI.
 * Args: uri, nettype
 * Returns: JSON with address, paymentId, amount, txDescription, recipientName, unknownParameters
 * or JSON with error field on failure
 */
std::string parseUri(const std::vector<std::string> &args) {
  std::string uri = args[0];
  int nettype = std::stoi(args[1]);
  Monero::Wallet* wallet = findWalletByNettype(nettype);

  std::string address;
  std::string paymentId;
  uint64_t amount = 0;
  std::string txDescription;
  std::string recipientName;
  std::vector<std::string> unknownParameters;
  std::string error;

  if (!wallet->parse_uri(uri, address, paymentId, amount, txDescription, recipientName, unknownParameters, error)) {
    return "{\"error\":\"" + jsonEscape(error) + "\"}";
  }

  std::string json = "{";
  json += "\"address\":\"" + jsonEscape(address) + "\",";
  json += "\"paymentId\":\"" + jsonEscape(paymentId) + "\",";
  json += "\"amount\":\"" + std::to_string(amount) + "\",";
  json += "\"txDescription\":\"" + jsonEscape(txDescription) + "\",";
  json += "\"recipientName\":\"" + jsonEscape(recipientName) + "\",";
  json += "\"unknownParameters\":[";
  for (size_t i = 0; i < unknownParameters.size(); ++i) {
    if (i > 0) json += ",";
    json += "\"" + jsonEscape(unknownParameters[i]) + "\"";
  }
  json += "]}";

  return json;
}

/**
 * Encode a monero: URI.
 * Args: address, paymentId, amount (atomic string), txDescription, recipientName, nettype
 * Returns: URI string, or JSON with error field on failure
 */
std::string encodeUri(const std::vector<std::string> &args) {
  std::string address = args[0];
  std::string paymentId = args[1];
  std::string amountStr = args[2];
  std::string txDescription = args[3];
  std::string recipientName = args[4];
  int nettype = std::stoi(args[5]);
  Monero::Wallet* wallet = findWalletByNettype(nettype);

  uint64_t amount = 0;
  if (!amountStr.empty() && amountStr != "0") {
    try {
      amount = std::stoull(amountStr);
    } catch (...) {
      return "{\"error\":\"Invalid amount: " + jsonEscape(amountStr) + "\"}";
    }
  }

  std::string error;
  std::string uri = wallet->make_uri(address, paymentId, amount, txDescription, recipientName, error);

  if (uri.empty()) {
    return "{\"error\":\"" + jsonEscape(error) + "\"}";
  }

  return uri;
}

/**
 * Set the API key for LWS requests.
 * Args: apiKey
 * Returns: "ok"
 */
std::string setLwsApiKey(const std::vector<std::string> &args) {
  std::string apiKey = args[0];
  lwsf::config::set_api_key(apiKey);
  return "ok";
}

/**
 * Enable or disable routing LWSF HTTP requests through the JS fetch bridge
 * (used for Nym mixnet support).
 *
 * Args:
 *   enabled  - "true" or "false"
 *   baseUrl  - scheme://host[:port] for the LWSF server; used when enabled
 * Returns: "ok"
 */
std::string setNymEnabled(const std::vector<std::string> &args) {
  const std::string& enabledStr = args[0];
  const std::string& baseUrl = args[1];
  const bool enabled = (enabledStr == "true" || enabledStr == "1");
  if (!g_wallets.empty()) {
    throw std::runtime_error(
        "Close all wallets before changing the Nym transport configuration");
  }
  nymfetch::setBaseUrl(baseUrl);
  nymfetch::setEnabled(enabled);
  return "ok";
}

/**
 * Resolve a pending nym fetch request. Called from JS when the fetch
 * completes successfully.
 *
 * Args:
 *   requestId   - id sent with the original nymFetchRequest event
 *   statusStr   - HTTP status code (stringified integer)
 *   bodyBase64  - response body, base64-encoded
 * Returns: "ok"
 */
std::string resolveFetch(const std::vector<std::string> &args) {
  const std::string& requestId = args[0];
  const std::string& statusStr = args[1];
  const std::string& bodyBase64 = args[2];
  int status = 0;
  try {
    status = std::stoi(statusStr);
  } catch (...) {
    status = 0;
  }
  nymfetch::resolveFetch(requestId, status, bodyBase64);
  return "ok";
}

/**
 * Reject a pending nym fetch request. Called from JS when the fetch fails.
 *
 * Args:
 *   requestId     - id sent with the original nymFetchRequest event
 *   errorMessage  - description of the failure
 * Returns: "ok"
 */
std::string rejectFetch(const std::vector<std::string> &args) {
  const std::string& requestId = args[0];
  const std::string& errorMessage = args[1];
  nymfetch::rejectFetch(requestId, errorMessage);
  return "ok";
}

/** Upper bound on subaddress materialization, so a corrupt index cannot
 *  make the wallet allocate unbounded rows on a single call. */
static const uint32_t MAX_SUBADDRESS_INDEX = 10000;

/**
 * Next unused receive subaddress for an account.
 *
 * Uses incoming payment minor indices (not the Subaddress row table): the row
 * table includes lookahead / previously materialized unused addresses, so
 * max(row)+1 would advance on every Receive open. The focused wallet query
 * avoids rebuilding the complete transaction history.
 *
 * Args: walletId, accountIndex
 * Returns: JSON with address, accountIndex and addressIndex
 */
std::string getNextSubaddress(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  uint32_t accountIndex = static_cast<uint32_t>(std::stoul(args[1]));

  Monero::Wallet* wallet = findWalletOrThrow(walletId).wallet;

  uint32_t addressIndex = wallet->nextUnusedSubaddressIndex(accountIndex);
  if (addressIndex > MAX_SUBADDRESS_INDEX) {
    throw std::runtime_error("Subaddress index out of range");
  }

  while (wallet->numSubaddresses(accountIndex) <= addressIndex) {
    wallet->addSubaddress(accountIndex, "");
  }

  std::string address = wallet->address(accountIndex, addressIndex);
  if (address.empty()) {
    throw std::runtime_error("Failed to derive subaddress");
  }

  std::string json = "{";
  json += "\"address\":\"" + jsonEscape(address) + "\",";
  json += "\"accountIndex\":" + std::to_string(accountIndex) + ",";
  json += "\"addressIndex\":" + std::to_string(addressIndex);
  json += "}";
  return json;
}

/** Args: walletId. Returns: [{index,label,balance,unlockedBalance}] */
std::string getAccounts(const std::vector<std::string> &args) {
  Monero::Wallet* wallet = findWalletOrThrow(args[0]).wallet;
  uint32_t count = wallet->numSubaddressAccounts();
  std::string json = "[";
  for (uint32_t i = 0; i < count; ++i) {
    if (i > 0) json += ",";
    json += "{\"index\":" + std::to_string(i) +
            ",\"label\":\"" + jsonEscape(wallet->getSubaddressLabel(i, 0)) +
            "\",\"balance\":\"" + std::to_string(wallet->balance(i)) +
            "\",\"unlockedBalance\":\"" + std::to_string(wallet->unlockedBalance(i)) + "\"}";
  }
  return json + "]";
}

/** Args: walletId, label. Returns: {index} */
std::string createAccount(const std::vector<std::string> &args) {
  Monero::Wallet* wallet = findWalletOrThrow(args[0]).wallet;
  wallet->addSubaddressAccount(args[1]);
  wallet->store("");
  notifyWalletFilesChanged(args[0]);
  return "{\"index\":" + std::to_string(wallet->numSubaddressAccounts() - 1) + "}";
}

/** Args: walletId, accountIndex. WalletStatus shape plus otherAccountsBalance. */
std::string getAccountStatus(const std::vector<std::string> &args) {
  WalletEntry& entry = findWalletOrThrow(args[0]);
  Monero::Wallet* wallet = entry.wallet;
  uint32_t accountIndex = static_cast<uint32_t>(std::stoul(args[1]));
  if (accountIndex >= wallet->numSubaddressAccounts()) {
    throw std::runtime_error("Account index out of range");
  }
  uint64_t balance = wallet->balance(accountIndex);
  uint64_t unlocked = wallet->unlockedBalance(accountIndex);
  uint64_t all = wallet->balanceAll();
  bool refreshed = entry.listener != nullptr && entry.listener->hasRefreshed();
  std::string json = "{";
  json += "\"syncedHeight\":" + std::to_string(wallet->blockChainHeight()) + ",";
  json += "\"networkHeight\":" + std::to_string(wallet->daemonBlockChainHeight()) + ",";
  json += "\"balance\":\"" + std::to_string(balance) + "\",";
  json += "\"unlockedBalance\":\"" + std::to_string(unlocked) + "\",";
  json += "\"otherAccountsBalance\":\"" + std::to_string(all > balance ? all - balance : 0) + "\",";
  json += "\"refreshed\":" + std::string(refreshed ? "true" : "false") + ",";
  json += walletStatusFields(wallet);
  return json + "}";
}

/**
 * Create a transaction from a specific subaddress account.
 * Args: walletId, addresses, amounts, priority, accountIndex
 * Returns: JSON with txid, signedTxHex, and fee
 */
std::string createTransactionFromAccount(const std::vector<std::string> &args) {
  WalletEntry& entry = findWalletOrThrow(args[0]);
  Monero::Wallet* wallet = entry.wallet;
  std::vector<std::string> addresses = splitString(args[1], ',');
  std::vector<std::string> amountStrs = splitString(args[2], ',');
  int priority = std::stoi(args[3]);
  uint32_t accountIndex = static_cast<uint32_t>(std::stoul(args[4]));
  if (accountIndex >= wallet->numSubaddressAccounts()) {
    throw std::runtime_error("Account index out of range");
  }
  if (addresses.empty() || addresses.size() != amountStrs.size()) {
    throw std::runtime_error("Addresses and amounts must have same length and not be empty");
  }
  std::vector<uint64_t> amounts;
  for (const auto& amt : amountStrs) amounts.push_back(std::stoull(amt));
  Monero::optional<std::vector<uint64_t>> optAmounts;
  if (addresses.size() == 1 && amounts[0] == 0) optAmounts = std::nullopt;
  else optAmounts = amounts;

  wallet->pauseRefresh();
  Monero::PendingTransaction* ptx = wallet->createTransactionMultDest(
    addresses, "", optAmounts, 0,
    static_cast<Monero::PendingTransaction::Priority>(priority), accountIndex);
  wallet->startRefresh();

  if (ptx == nullptr) throw std::runtime_error("Failed to create transaction");
  if (ptx->status() != Monero::PendingTransaction::Status_Ok) {
    std::string error = ptx->errorString();
    wallet->disposeTransaction(ptx);
    throw std::runtime_error("Transaction error: " + error);
  }
  std::vector<std::string> txIds = ptx->txid();
  if (txIds.size() != 1) {
    std::string count = std::to_string(txIds.size());
    wallet->disposeTransaction(ptx);
    throw std::runtime_error("Transaction would split into " + count + " transactions; send a smaller amount");
  }
  std::string txHash = txIds[0];
  uint64_t fee = ptx->fee();
  retainTx(args[0], wallet, txHash, ptx);
  return "{\"txid\":\"" + txHash + "\",\"signedTxHex\":\"" + txHash + "\",\"fee\":\"" + std::to_string(fee) + "\"}";
}

/**
 * Get the receive address at a subaddress index, creating rows up to it.
 *
 * wallet2 only scans for subaddresses it holds a row for: computing the
 * address is not enough, the index must be materialized via addSubaddress
 * or payments to it are never detected. numSubaddresses is the row count,
 * so rows exist for indices [0, numSubaddresses).
 *
 * Args: walletId, accountIndex, addressIndex
 * Returns: JSON with address, accountIndex and addressIndex
 */
std::string getSubaddress(const std::vector<std::string> &args) {
  std::string walletId = args[0];
  uint32_t accountIndex = static_cast<uint32_t>(std::stoul(args[1]));
  uint32_t addressIndex = static_cast<uint32_t>(std::stoul(args[2]));

  if (addressIndex > MAX_SUBADDRESS_INDEX) {
    throw std::runtime_error("Subaddress index out of range");
  }

  WalletEntry& entry = findWalletOrThrow(walletId);
  Monero::Wallet* wallet = entry.wallet;

  while (wallet->numSubaddresses(accountIndex) <= addressIndex) {
    wallet->addSubaddress(accountIndex, "");
  }

  std::string address = wallet->address(accountIndex, addressIndex);
  if (address.empty()) {
    throw std::runtime_error("Failed to derive subaddress");
  }

  std::string json = "{";
  json += "\"address\":\"" + jsonEscape(address) + "\",";
  json += "\"accountIndex\":" + std::to_string(accountIndex) + ",";
  json += "\"addressIndex\":" + std::to_string(addressIndex);
  json += "}";
  return json;
}

const MoneroMethod moneroMethods[] = {
  { "hello", 0, hello },
  { "generateWallet", 2, generateWallet },
  { "seedAndKeysFromMnemonic", 2, seedAndKeysFromMnemonic },
  { "getNetworkBlockHeight", 7, getNetworkBlockHeight },
  { "discoverTlsPeerIdentity", 2, discoverTlsPeerIdentity },
  { "isValidAddress", 2, isValidAddress },
  { "openWallet", 11, openWallet },
  { "getWalletStatus", 1, getWalletStatus },
  { "getAllTransactions", 4, getAllTransactions },
  { "getPendingTransactions", 3, getPendingTransactions },
  { "closeWallet", 1, closeWallet },
  { "deleteWallet", 3, deleteWallet },
  { "createTransaction", 5, createTransaction },
  { "broadcastTransaction", 3, broadcastTransaction },
  { "parseUri", 2, parseUri },
  { "encodeUri", 6, encodeUri },
  { "setLwsApiKey", 1, setLwsApiKey },
  { "setNymEnabled", 2, setNymEnabled },
  { "resolveFetch", 3, resolveFetch },
  { "rejectFetch", 2, rejectFetch },
  { "getSubaddress", 3, getSubaddress },
  { "getNextSubaddress", 2, getNextSubaddress },
  { "getAccounts", 1, getAccounts },
  { "createAccount", 2, createAccount },
  { "getAccountStatus", 2, getAccountStatus },
  { "createTransactionFromAccount", 5, createTransactionFromAccount },
};

const unsigned moneroMethodCount = std::end(moneroMethods) - std::begin(moneroMethods);
