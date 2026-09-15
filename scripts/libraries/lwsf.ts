import { readFile, writeFile } from 'fs/promises'
import { join } from 'path'

import { getRepo } from '../utils/common'
import { defineLib } from '../utils/lib'
import { addTask } from '../utils/tasks'

const moneroHash = '38bc62741b82cca179fb8e3437a388b0e0f67842' // Nov 7, 2025
// const moneroHash = '1c9686cb45bec8cd1ca5142426b9ea9458ac4384' // Last compatible version?

addTask({
  name: 'monero.clone',
  cacheTag: `${moneroHash}-next-subaddress-v2-verified-tls-v2`,
  async run(build) {
    await getRepo(
      'monero',
      'https://github.com/monero-project/monero.git',
      moneroHash
    )

    // Hack the build:
    const cmakePath = join(build.basePath, 'monero', 'CMakeLists.txt')
    const cmakeList = await readFile(cmakePath, 'utf8')
    await writeFile(
      cmakePath,
      cmakeList
        .replace(
          '  forbid_undefined_symbols()',
          '# $& # Disabled by react-native build'
        )
        .replace(
          'INCLUDE(CmakeLists_IOS.txt)',
          '# $& # Disabled by react-native build'
        ),
      'utf8'
    )

    const minerPath = join(
      build.basePath,
      'monero/src/cryptonote_basic/miner.cpp'
    )
    const minerCpp = await readFile(minerPath, 'utf8')
    await writeFile(
      minerPath,
      minerCpp
        .replace(
          '#include <IOKit/IOKitLib.h>',
          '// $& # Disabled by react-native build'
        )
        .replace(
          '#include <IOKit/ps/IOPSKeys.h>',
          '// $& # Disabled by react-native build'
        )
        .replace(
          '#include <IOKit/ps/IOPowerSources.h>',
          '// $& # Disabled by react-native build'
        ),
      'utf8'
    )

    // Extend epee SSL options with an observation callback for explicit TOFU
    // discovery, and allow an explicit CA file while retaining system_ca's
    // hostname verification.
    const netSslHeaderPath = join(
      build.basePath,
      'monero/contrib/epee/include/net/net_ssl.h'
    )
    const netSslHeader = await readFile(netSslHeaderPath, 'utf8')
    const patchedNetSslHeader = netSslHeader
      .replace(
        '#include <chrono>',
        `#include <chrono>
#include <functional>`
      )
      .replace(
        '    ssl_verification_t verification;',
        `    ssl_verification_t verification;
    std::function<void(const std::string&)> peer_fingerprint_callback;`
      )
    if (!patchedNetSslHeader.includes('peer_fingerprint_callback')) {
      throw new Error('Monero net_ssl.h observer patch anchor did not match')
    }
    await writeFile(netSslHeaderPath, patchedNetSslHeader, 'utf8')

    const netSslCppPath = join(
      build.basePath,
      'monero/contrib/epee/src/net_ssl.cpp'
    )
    const netSslCpp = await readFile(netSslCppPath, 'utf8')
    const patchedNetSslCpp = netSslCpp
      .replace(
        `#else
      ssl_context.set_default_verify_paths();
#endif`,
        `#else
      if (ca_path.empty())
        ssl_context.set_default_verify_paths();
      else
      {
        const boost::system::error_code err = load_ca_file(ssl_context, ca_path);
        if (err)
          throw boost::system::system_error{err, "Failed to load CA file at " + ca_path};
      }
#endif`
      )
      .replace(
        `  MDEBUG("SSL handshake success");
  return true;`,
        `  if (peer_fingerprint_callback)
  {
    X509* cert = SSL_get1_peer_certificate(socket.native_handle());
    if (!cert)
    {
      MERROR("TLS peer did not provide a certificate");
      return false;
    }
    try
    {
      peer_fingerprint_callback(get_hr_ssl_fingerprint(cert));
    }
    catch (...)
    {
      X509_free(cert);
      throw;
    }
    X509_free(cert);
  }
  MDEBUG("SSL handshake success");
  return true;`
      )
      .replace(
        '(verification != ssl_verification_t::system_ca || host.empty() || MONERO_HOSTNAME_VERIFY(host)(preverified, ctx))',
        `((verification != ssl_verification_t::system_ca &&
          verification != ssl_verification_t::user_ca) ||
         host.empty() || MONERO_HOSTNAME_VERIFY(host)(preverified, ctx))`
      )
    if (
      !patchedNetSslCpp.includes('SSL_get1_peer_certificate') ||
      !patchedNetSslCpp.includes('Failed to load CA file at') ||
      !patchedNetSslCpp.includes('verification != ssl_verification_t::user_ca')
    ) {
      throw new Error('Monero net_ssl.cpp TLS patch anchor did not match')
    }
    await writeFile(netSslCppPath, patchedNetSslCpp, 'utf8')

    // Add a focused wallet API query for finding the next receive
    // subaddress. TransactionHistory::refresh rebuilds incoming and outgoing
    // history objects, which is unnecessarily expensive for this lookup.
    const walletApiPath = join(
      build.basePath,
      'monero/src/wallet/api/wallet2_api.h'
    )
    const walletApiHeader = await readFile(walletApiPath, 'utf8')
    const patchedWalletApiHeader = walletApiHeader
      .replace(
        '#include <vector>',
        `#include <vector>
#include "net/net_ssl.h"`
      )
      .replace(
        '    virtual bool init(const std::string &daemon_address, uint64_t upper_transaction_size_limit = 0, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") = 0;',
        `    virtual bool init(const std::string &daemon_address, uint64_t upper_transaction_size_limit = 0, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") = 0;
    virtual bool initWithTls(const std::string &daemon_address, uint64_t upper_transaction_size_limit, const std::string &daemon_username, const std::string &daemon_password, bool lightWallet, const std::string &proxy_address, epee::net_utils::ssl_options_t ssl_options) = 0;`
      )
      .replace(
        '    virtual void setDaemonAddress(const std::string &address) = 0;',
        `    virtual void setDaemonAddress(const std::string &address) = 0;
    virtual void setDaemonAddressWithTls(const std::string &address, epee::net_utils::ssl_options_t ssl_options, const std::string &proxy_address) = 0;`
      )
      .replace(
        '    virtual size_t numSubaddresses(uint32_t accountIndex) const = 0;',
        `    virtual size_t numSubaddresses(uint32_t accountIndex) const = 0;
    virtual uint32_t nextUnusedSubaddressIndex(uint32_t accountIndex) const = 0;`
      )
    if (
      !patchedWalletApiHeader.includes('virtual bool initWithTls') ||
      !patchedWalletApiHeader.includes('setDaemonAddressWithTls')
    ) {
      throw new Error('Monero wallet2_api.h TLS patch anchor did not match')
    }
    await writeFile(walletApiPath, patchedWalletApiHeader, 'utf8')

    const walletHeaderPath = join(
      build.basePath,
      'monero/src/wallet/api/wallet.h'
    )
    const walletHeader = await readFile(walletHeaderPath, 'utf8')
    const patchedWalletHeader = walletHeader
      .replace(
        '    bool init(const std::string &daemon_address, uint64_t upper_transaction_size_limit = 0, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") override;',
        `    bool init(const std::string &daemon_address, uint64_t upper_transaction_size_limit = 0, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") override;
    bool initWithTls(const std::string &daemon_address, uint64_t upper_transaction_size_limit, const std::string &daemon_username, const std::string &daemon_password, bool lightWallet, const std::string &proxy_address, epee::net_utils::ssl_options_t ssl_options) override;`
      )
      .replace(
        '    bool doInit(const std::string &daemon_address, const std::string &proxy_address, uint64_t upper_transaction_size_limit = 0, bool ssl = false);',
        '    bool doInit(const std::string &daemon_address, const std::string &proxy_address, uint64_t upper_transaction_size_limit, epee::net_utils::ssl_options_t ssl_options);'
      )
      .replace(
        '    size_t numSubaddresses(uint32_t accountIndex) const override;',
        `    size_t numSubaddresses(uint32_t accountIndex) const override;
    uint32_t nextUnusedSubaddressIndex(uint32_t accountIndex) const override;`
      )
    if (!patchedWalletHeader.includes('bool initWithTls')) {
      throw new Error('Monero wallet.h TLS patch anchor did not match')
    }
    await writeFile(walletHeaderPath, patchedWalletHeader, 'utf8')

    const walletCppPath = join(
      build.basePath,
      'monero/src/wallet/api/wallet.cpp'
    )
    const walletCpp = await readFile(walletCppPath, 'utf8')
    const patchedWalletCpp = walletCpp
      .replace(
        '#include <unordered_map>',
        `#include <limits>
#include <unordered_map>`
      )
      .replace(
        `bool WalletImpl::init(const std::string &daemon_address, uint64_t upper_transaction_size_limit, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool lightWallet, const std::string &proxy_address)
{
    clearStatus();
    if(daemon_username != "")
        m_daemon_login.emplace(daemon_username, daemon_password);
    return doInit(daemon_address, proxy_address, upper_transaction_size_limit, use_ssl);
}`,
        `bool WalletImpl::init(const std::string &daemon_address, uint64_t upper_transaction_size_limit, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool lightWallet, const std::string &proxy_address)
{
    epee::net_utils::ssl_options_t ssl_options{
        use_ssl
            ? epee::net_utils::ssl_support_t::e_ssl_support_enabled
            : epee::net_utils::ssl_support_t::e_ssl_support_autodetect};
    return initWithTls(daemon_address, upper_transaction_size_limit,
                       daemon_username, daemon_password, lightWallet,
                       proxy_address, std::move(ssl_options));
}

bool WalletImpl::initWithTls(const std::string &daemon_address, uint64_t upper_transaction_size_limit, const std::string &daemon_username, const std::string &daemon_password, bool, const std::string &proxy_address, epee::net_utils::ssl_options_t ssl_options)
{
    clearStatus();
    if(daemon_username != "")
        m_daemon_login.emplace(daemon_username, daemon_password);
    return doInit(daemon_address, proxy_address, upper_transaction_size_limit,
                  std::move(ssl_options));
}`
      )
      .replace(
        'bool WalletImpl::doInit(const string &daemon_address, const std::string &proxy_address, uint64_t upper_transaction_size_limit, bool ssl)',
        'bool WalletImpl::doInit(const string &daemon_address, const std::string &proxy_address, uint64_t upper_transaction_size_limit, epee::net_utils::ssl_options_t ssl_options)'
      )
      .replace(
        '    if (!m_wallet->init(daemon_address, m_daemon_login, proxy_address, upper_transaction_size_limit))',
        `    // Preserve the caller's exact per-node TLS verification policy.
    if (!m_wallet->init(daemon_address, m_daemon_login, proxy_address,
                        upper_transaction_size_limit, true,
                        std::move(ssl_options)))`
      )
      .replace(
        '    bool rescan = m_refreshShouldRescan.exchange(false);',
        `    bool rescan = m_refreshShouldRescan.exchange(false);
    bool refresh_completed = false;`
      )
      .replace(
        `        if (daemonSynced()) {
            if(rescan)
                m_wallet->rescan_blockchain(false);
            m_wallet->refresh(trustedDaemon());`,
        `        if (daemonSynced()) {
            clearStatus();
            if(rescan)
                m_wallet->rescan_blockchain(false);
            m_wallet->refresh(trustedDaemon());`
      )
      .replace(
        '            m_wallet->refresh(trustedDaemon());',
        `            m_wallet->refresh(trustedDaemon());
            refresh_completed = true;`
      )
      .replace(
        `        } else {
           LOG_PRINT_L3(__FUNCTION__ << ": skipping refresh - daemon is not synced");
        }`,
        `        } else {
           LOG_PRINT_L3(__FUNCTION__ << ": skipping refresh - daemon is not synced");
           // react-native build: a rejected TLS handshake or unreachable daemon
           // is otherwise invisible to the bridge, which only ever sees
           // "refreshed" staying false until its own stall timeout.
           setStatusError(tr("wallet is not connected to daemon or daemon is not synced"));
        }`
      )
      .replace(
        `    }while(!rescan && (rescan=m_refreshShouldRescan.exchange(false))); // repeat if not rescanned and rescan was requested

    if (m_wallet2Callback->getListener()) {`,
        `    }while(!rescan && (rescan=m_refreshShouldRescan.exchange(false))); // repeat if not rescanned and rescan was requested

    if (refresh_completed && m_wallet2Callback->getListener()) {`
      )
      .replace(
        `size_t WalletImpl::numSubaddresses(uint32_t accountIndex) const
{
    return m_wallet->get_num_subaddresses(accountIndex);
}`,
        `size_t WalletImpl::numSubaddresses(uint32_t accountIndex) const
{
    return m_wallet->get_num_subaddresses(accountIndex);
}

uint32_t WalletImpl::nextUnusedSubaddressIndex(uint32_t accountIndex) const
{
    bool found = false;
    uint32_t max_used = 0;

    std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
    m_wallet->get_payments(payments, 0, (uint64_t)-1, accountIndex);
    for (const auto& payment : payments)
    {
        const auto& index = payment.second.m_subaddr_index;
        if (!found || index.minor > max_used)
        {
            found = true;
            max_used = index.minor;
        }
    }

    std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> pool_payments;
    m_wallet->get_unconfirmed_payments(pool_payments, accountIndex);
    for (const auto& payment : pool_payments)
    {
        const auto& index = payment.second.m_pd.m_subaddr_index;
        if (!found || index.minor > max_used)
        {
            found = true;
            max_used = index.minor;
        }
    }

    if (!found)
        return 0;
    if (max_used == std::numeric_limits<uint32_t>::max())
        throw std::runtime_error("Subaddress index overflow");
    return max_used + 1;
}`
      )
    if (
      !patchedWalletCpp.includes('bool WalletImpl::initWithTls') ||
      !patchedWalletCpp.includes('std::move(ssl_options)') ||
      !patchedWalletCpp.includes('bool refresh_completed = false;') ||
      !patchedWalletCpp.includes(
        'wallet is not connected to daemon or daemon is not synced'
      ) ||
      !patchedWalletCpp.includes(
        'refresh_completed && m_wallet2Callback->getListener()'
      )
    ) {
      throw new Error(
        'Monero wallet.cpp TLS patch anchor did not match the pinned source'
      )
    }
    await writeFile(walletCppPath, patchedWalletCpp, 'utf8')

    const walletManagerHeaderPath = join(
      build.basePath,
      'monero/src/wallet/api/wallet_manager.h'
    )
    const walletManagerHeader = await readFile(walletManagerHeaderPath, 'utf8')
    const patchedWalletManagerHeader = walletManagerHeader.replace(
      '    void setDaemonAddress(const std::string &address) override;',
      `    void setDaemonAddress(const std::string &address) override;
    void setDaemonAddressWithTls(const std::string &address, epee::net_utils::ssl_options_t ssl_options, const std::string &proxy_address) override;`
    )
    if (!patchedWalletManagerHeader.includes('setDaemonAddressWithTls')) {
      throw new Error('Monero wallet_manager.h TLS patch anchor did not match')
    }
    await writeFile(walletManagerHeaderPath, patchedWalletManagerHeader, 'utf8')

    // WalletManager powers the standalone network-height probe. It has a
    // separate HTTP client from wallet2, so propagate the same exact policy.
    const walletManagerCppPath = join(
      build.basePath,
      'monero/src/wallet/api/wallet_manager.cpp'
    )
    const walletManagerCpp = await readFile(walletManagerCppPath, 'utf8')
    const patchedWalletManagerCpp = walletManagerCpp
      .replace(
        '#include "version.h"',
        `#include "version.h"
#include "net/parse.h"
#include "net/socks_connect.h"`
      )
      .replace(
        `void WalletManagerImpl::setDaemonAddress(const std::string &address)
{
    m_http_client.set_server(address, boost::none);
}`,
        `void WalletManagerImpl::setDaemonAddress(const std::string &address)
{
    m_http_client.set_server(address, boost::none);
}

void WalletManagerImpl::setDaemonAddressWithTls(
    const std::string &address,
    epee::net_utils::ssl_options_t ssl_options,
    const std::string &proxy_address)
{
    if (proxy_address.empty())
        m_http_client.set_connector(epee::net_utils::direct_connect{});
    else
    {
        auto endpoint = net::get_tcp_endpoint(proxy_address);
        if (!endpoint)
            throw std::runtime_error("Invalid SOCKS proxy address");
        m_http_client.set_connector(net::socks::connector{std::move(*endpoint)});
    }
    m_http_client.set_server(address, boost::none, std::move(ssl_options));
}`
      )
    if (!patchedWalletManagerCpp.includes('setDaemonAddressWithTls')) {
      throw new Error(
        'Monero wallet_manager.cpp TLS patch anchor did not match the pinned source'
      )
    }
    await writeFile(walletManagerCppPath, patchedWalletManagerCpp, 'utf8')

    // Patch monero/src/net/http.cpp so that `client_factory::create()`
    // returns a nym-aware http client when the nym-fetch interceptor is
    // enabled. This routes all wallet2-driven (monerod) HTTP calls through
    // the JS fetch bridge the same way the LWSF backend is routed via the
    // rpc.cpp patch. When nym is disabled the factory keeps returning the
    // default `client` and behavior is unchanged.
    const httpCppPath = join(build.basePath, 'monero/src/net/http.cpp')
    const httpCpp = await readFile(httpCppPath, 'utf8')
    await writeFile(
      httpCppPath,
      httpCpp
        .replace(
          '#include "socks_connect.h"',
          `#include "socks_connect.h"

// --- react-native build: nym-fetch interceptor ------------------------------
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <stdexcept>

#include "net/http_base.h"

// Forward declarations for the nym-fetch interceptor. The actual symbols
// are defined in src/monero-wrapper/nym-fetch.cpp and linked together with
// the monero static libraries in the final ffi module.
namespace nymfetch {
  struct Response { int status; std::string body; };
  bool isEnabled();
  std::string getBaseUrl();
  Response performFetch(
      const std::string& url,
      const std::string& method,
      const std::string& headersJson,
      const std::string& body,
      std::uint64_t timeoutMs);
}

namespace rn_nym_http {

// Minimal concrete abstract_http_client that routes every invoke() call
// through nymfetch::performFetch. Connect / disconnect / proxy operations
// are accepted but treated as no-ops because the JS side owns the actual
// transport (mixFetch through the Nym mixnet).
class NymHttpClient final : public epee::net_utils::http::abstract_http_client {
public:
  NymHttpClient() = default;
  ~NymHttpClient() override = default;

  bool set_proxy(const std::string& /*address*/) override { return true; }

  void set_server(std::string host,
                  std::string port,
                  boost::optional<epee::net_utils::http::login> /*user*/,
                  epee::net_utils::ssl_options_t ssl_options =
                      epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
      override {
    if (ssl_options.verification !=
        epee::net_utils::ssl_verification_t::none) {
      throw std::runtime_error(
          "Nym transport cannot enforce native TLS verification policy");
    }
    m_host = std::move(host);
    m_port = std::move(port);
    m_use_https = (ssl_options.support ==
                   epee::net_utils::ssl_support_t::e_ssl_support_enabled);
  }

  void set_auto_connect(bool /*auto_connect*/) override {}
  bool connect(std::chrono::milliseconds /*timeout*/) override { return true; }
  bool disconnect() override { return true; }
  bool is_connected(bool* ssl = nullptr) override {
    if (ssl != nullptr) *ssl = m_use_https;
    return true;
  }

  bool invoke(const boost::string_ref uri,
              const boost::string_ref method,
              const boost::string_ref body,
              std::chrono::milliseconds timeout,
              const epee::net_utils::http::http_response_info**
                  ppresponse_info = nullptr,
              const epee::net_utils::http::fields_list& additional_params =
                  epee::net_utils::http::fields_list()) override {
    return dispatch(uri, method, body, timeout, ppresponse_info,
                    additional_params);
  }

  bool invoke_get(const boost::string_ref uri,
                  std::chrono::milliseconds timeout,
                  const std::string& body = std::string(),
                  const epee::net_utils::http::http_response_info**
                      ppresponse_info = nullptr,
                  const epee::net_utils::http::fields_list& additional_params =
                      epee::net_utils::http::fields_list()) override {
    return dispatch(uri, boost::string_ref("GET", 3),
                    boost::string_ref(body.data(), body.size()), timeout,
                    ppresponse_info, additional_params);
  }

  std::uint64_t get_bytes_sent() const override { return m_bytes_sent; }
  std::uint64_t get_bytes_received() const override { return m_bytes_received; }

private:
  bool dispatch(const boost::string_ref uri,
                const boost::string_ref method,
                const boost::string_ref body,
                std::chrono::milliseconds timeout,
                const epee::net_utils::http::http_response_info**
                    ppresponse_info,
                const epee::net_utils::http::fields_list& additional_params) {
    // Monerod wallet2 calls carry their target through set_server(), so
    // use that per-client state instead of the global LWSF base URL.
    if (m_host.empty()) return false;
    const bool use_https = m_use_https;
    std::string base = (use_https ? "https://" : "http://") + m_host;
    if (!m_port.empty()) base += ":" + m_port;
    std::string path(uri.data(), uri.size());
    if (path.empty() || path.front() != '/') path.insert(path.begin(), '/');
    const std::string url = base + path;

    // Serialize additional_params + a Host header into a tiny hand-rolled
    // JSON object. We keep this dependency-free to avoid pulling rapidjson
    // through the epee layer.
    std::string headersJson = "{";
    bool first = true;
    const auto appendHeader = [&](const std::string& name,
                                  const std::string& value) {
      if (!first) headersJson += ",";
      first = false;
      headersJson += "\\"";
      headersJson += escapeJson(name);
      headersJson += "\\":\\"";
      headersJson += escapeJson(value);
      headersJson += "\\"";
    };
    for (const auto& kv : additional_params) {
      appendHeader(kv.first, kv.second);
    }
    headersJson += "}";

    const std::string method_str(method.data(), method.size());
    const std::string body_str(body.data(), body.size());

    m_bytes_sent += body.size();

    try {
      const auto r = nymfetch::performFetch(
          url, method_str, headersJson, body_str,
          static_cast<std::uint64_t>(
              timeout.count() > 0 ? timeout.count() : 60000));
      if (r.status <= 0 || r.status > std::numeric_limits<int>::max()) {
        return false;
      }
      m_response_info.clear();
      m_response_info.m_response_code = r.status;
      m_response_info.m_body = r.body;
      m_response_info.m_http_ver_hi = 1;
      m_response_info.m_http_ver_lo = 1;
      m_bytes_received += r.body.size();
      if (ppresponse_info != nullptr) {
        *ppresponse_info = std::addressof(m_response_info);
      }
      return true;
    } catch (const std::exception&) {
      return false;
    }
  }

  static std::string escapeJson(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
      switch (c) {
        case '"': out += "\\\\\\""; break;
        case '\\\\': out += "\\\\\\\\"; break;
        case '\\n': out += "\\\\n"; break;
        case '\\r': out += "\\\\r"; break;
        case '\\t': out += "\\\\t"; break;
        default:
          if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\\\u%04x",
                          static_cast<unsigned>(c) & 0xff);
            out += buf;
          } else {
            out += c;
          }
      }
    }
    return out;
  }

  epee::net_utils::http::http_response_info m_response_info;
  std::string m_host;
  std::string m_port;
  bool m_use_https = false;
  std::uint64_t m_bytes_sent = 0;
  std::uint64_t m_bytes_received = 0;
};

} // namespace rn_nym_http
// --- end react-native build patch -------------------------------------------`
        )
        .replace(
          `std::unique_ptr<epee::net_utils::http::abstract_http_client> client_factory::create()
{
  return std::unique_ptr<epee::net_utils::http::abstract_http_client>(new client());
}`,
          `std::unique_ptr<epee::net_utils::http::abstract_http_client> client_factory::create()
{
  // react-native build: divert to the JS fetch bridge when enabled so
  // monerod RPC calls travel through Nym like the lwsf backend does.
  if (nymfetch::isEnabled()) {
    return std::unique_ptr<epee::net_utils::http::abstract_http_client>(
        new rn_nym_http::NymHttpClient());
  }
  return std::unique_ptr<epee::net_utils::http::abstract_http_client>(new client());
}`
        ),
      'utf8'
    )

    return moneroHash
  }
})

export const lwsf = defineLib({
  name: 'lwsf',
  // Bump this whenever the rpc.cpp / config patch below changes, or the build
  // silently reuses the cached (unpatched) library. The literal tag does not
  // hash the patch content, so edits here are invisible to the cache otherwise.
  cacheTag: '4-da8e261-txcap-nym-timeout-next-subaddress-tls-policy-v2',
  libDeps: ['boost', 'libsodium', 'libunbound', 'libzmq', 'openssl'],
  deps: ['monero.clone'],

  url: 'https://github.com/vtnerd/lwsf.git',
  // Dec 13, 2025. Includes upstream da8e261 "Update get_address_txs tx array
  // constraint": the old pin rejected any get_address_txs response with more
  // than config::max_txes_in_rpc = 2048 transactions, permanently bricking
  // sync for wallets whose (decoy-inflated) tx list crossed that size.
  hash: 'da8e2617958312f10fe4406808c2a951c5cf0a09',

  async build(build, platform, prefixPath) {
    // Patch rpc.cpp to support api_key injection in HTTP requests
    // and to optionally route requests through a JS-side fetch bridge
    // (used for Nym mixnet support).
    const rpcPath = join(build.cwd, 'src/rpc.cpp')
    const rpcCpp = await readFile(rpcPath, 'utf8')
    const patchedRpcCpp = rpcCpp
      // Add api_key storage + nym-fetch declarations after includes.
      .replace(
        '#include "wire/wrappers_impl.h"',
        `#include "wire/wrappers_impl.h"
#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>

// API key storage for request injection (added by react-native build)
namespace lwsf { namespace config {
  static std::string g_api_key;
  const std::string& api_key() { return g_api_key; }
  void set_api_key(const std::string& k) { g_api_key = k; }
}}

// Forward declarations for the nym-fetch interceptor (added by
// react-native build). These symbols are defined in nym-fetch.cpp and
// linked into the ffi module at link time.
namespace nymfetch {
  struct Response { int status; std::string body; };
  bool isEnabled();
  std::string getBaseUrl();
  Response performFetch(
      const std::string& url,
      const std::string& method,
      const std::string& headersJson,
      const std::string& body,
      std::uint64_t timeoutMs);
}`
      )
      // Modify invoke_payload to (1) inject api_key into JSON body and
      // (2) redirect to the JS fetch bridge when Nym is enabled.
      .replace(
        `expect<std::string> invoke_payload(http_client& client, const boost::string_ref prefix, boost::string_ref endpoint, const epee::byte_slice payload)
  {
    static const epee::net_utils::http::fields_list headers{
      {"Content-Type", "application/json; charset=utf-8"}
    };

    if (!client.is_connected())
    {
      if (!client.connect(config::connect_timeout))
        return {error::no_response};
    }

    std::string real;
    if (!prefix.empty())
    {
      real = std::string{prefix} + std::string{endpoint};
      endpoint = real;
    }

    const epee::net_utils::http::http_response_info* response = nullptr;
    if (!client.invoke(endpoint, "POST", {reinterpret_cast<const char*>(payload.data()), payload.size()}, config::rpc_timeout, std::addressof(response), headers))
      return {error::no_response};`,
        `expect<std::string> invoke_payload(http_client& client, const boost::string_ref prefix, boost::string_ref endpoint, const epee::byte_slice payload)
  {
    static const epee::net_utils::http::fields_list headers{
      {"Content-Type", "application/json; charset=utf-8"}
    };

    std::string real;
    if (!prefix.empty())
    {
      real = std::string{prefix} + std::string{endpoint};
      endpoint = real;
    }

    // Inject api_key if set (added by react-native build)
    std::string body_str;
    const std::string& key = config::api_key();
    if (!key.empty()) {
      std::string original(reinterpret_cast<const char*>(payload.data()), payload.size());
      size_t pos = original.rfind('}');
      if (pos != std::string::npos && pos > 0) {
        body_str = original.substr(0, pos);
        if (original[pos-1] != '{') body_str += ",";
        body_str += "\\"api_key\\":\\"" + key + "\\"}";
      } else {
        body_str = original;
      }
    } else {
      body_str.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
    }

    // Nym path: delegate to JS fetch bridge instead of hitting the network
    // directly. The JS layer is responsible for actually executing the
    // request through mixFetch. This must run before the socket connect
    // below: a Nym wallet must never open a direct TCP connection to the
    // daemon.
    if (nymfetch::isEnabled()) {
      const std::string base = nymfetch::getBaseUrl();
      if (base.empty()) return {error::no_response};
      std::string path(endpoint.data(), endpoint.size());
      if (path.empty() || path.front() != '/') path.insert(path.begin(), '/');
      const std::string url = base + path;
      try {
        // Nym mixnet round-trips routinely exceed the config::rpc_timeout
        // used for the direct client below (the mixFetch client itself allows
        // 300s). A single-shot spend RPC (get_random_outs, submit_raw_tx) has
        // no retry, so a short budget makes LWS sends over Nym fail deterministically
        // while the retrying sync loop merely limps. Give the Nym path a generous
        // budget instead.
        const std::uint64_t nymTimeoutMs = 120000;
        const auto r = nymfetch::performFetch(
          url, "POST",
          std::string("{\\"Content-Type\\":\\"application/json; charset=utf-8\\"}"),
          body_str,
          nymTimeoutMs);
        if (r.status == 200 || r.status == 201) return r.body;
        if (r.status <= 0 || std::numeric_limits<int>::max() < r.status)
          return {error::invalid_code};
        return {error(int(r.status))};
      } catch (const std::exception&) {
        return {error::no_response};
      }
    }

    if (!client.is_connected())
    {
      if (!client.connect(config::connect_timeout))
        return {error::no_response};
    }

    const epee::net_utils::http::http_response_info* response = nullptr;
    if (!client.invoke(endpoint, "POST", body_str, config::rpc_timeout, std::addressof(response), headers))
      return {error::no_response};`
      )
    // Anchored replaces silently no-op when upstream drifts; fail the build
    // instead of shipping an unpatched (no api_key, no Nym) client.
    if (
      !patchedRpcCpp.includes('void set_api_key') ||
      !patchedRpcCpp.includes('client.invoke(endpoint, "POST", body_str')
    ) {
      throw new Error(
        'lwsf rpc.cpp patch anchors did not match the pinned source'
      )
    }
    await writeFile(rpcPath, patchedRpcCpp, 'utf8')
    build.log('Patched rpc.cpp for api_key and nym-fetch support')

    // A refresh callback means server data was merged successfully. Upstream
    // also emits it from an early-return guard on login/RPC failure, which
    // makes failed TLS handshakes look like a completed first refresh.
    const lwsfBackendPath = join(build.cwd, 'src/backend.cpp')
    const lwsfBackend = await readFile(lwsfBackendPath, 'utf8')
    const patchedLwsfBackend = lwsfBackend
      .replace(
        '    std::unique_ptr<wallet, call_refreshed> refresh_on_exit{this};',
        '    // Failed early returns must not emit WalletListener::refreshed().'
      )
      .replace(
        '    refresh_on_exit.release(); // release before acquiring `sync_listener`.',
        '    // The explicit callback below is the successful refresh signal.'
      )
    if (patchedLwsfBackend.includes('refresh_on_exit')) {
      throw new Error(
        'lwsf backend.cpp refresh-result patch anchor did not match'
      )
    }
    await writeFile(lwsfBackendPath, patchedLwsfBackend, 'utf8')

    const lwsfWalletHeaderPath = join(build.cwd, 'src/wallet.h')
    const lwsfWalletHeader = await readFile(lwsfWalletHeaderPath, 'utf8')
    const patchedLwsfWalletHeader = lwsfWalletHeader
      .replace(
        '    virtual bool init(const std::string &daemon_address, uint64_t, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") override;',
        `    virtual bool init(const std::string &daemon_address, uint64_t, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") override;
    virtual bool initWithTls(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool lightWallet, const std::string &proxy_address, epee::net_utils::ssl_options_t ssl_options) override;`
      )
      .replace(
        '    virtual size_t numSubaddresses(uint32_t accountIndex) const override;',
        `    virtual size_t numSubaddresses(uint32_t accountIndex) const override;
    virtual uint32_t nextUnusedSubaddressIndex(uint32_t accountIndex) const override;`
      )
    if (!patchedLwsfWalletHeader.includes('initWithTls')) {
      throw new Error('lwsf wallet.h TLS patch anchor did not match')
    }
    await writeFile(lwsfWalletHeaderPath, patchedLwsfWalletHeader, 'utf8')

    const lwsfWalletCppPath = join(build.cwd, 'src/wallet.cpp')
    const lwsfWalletCpp = await readFile(lwsfWalletCppPath, 'utf8')
    const patchedLwsfWalletCpp = lwsfWalletCpp
      .replace(
        `  bool wallet::init(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool light_wallet, const std::string &proxy_address)
  {
    if (!light_wallet)
      throw std::invalid_argument{"Only light_wallets are supported with this instance"};

    try
    {
      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(daemon_address, url))
        throw std::runtime_error{"Invalid LWS URL: " + daemon_address};

      if (!proxy_address.empty() && !setProxy(proxy_address))
        return false;

      boost::optional<epee::net_utils::http::login> login;
      if (!daemon_username.empty() || !daemon_password.empty())
        login.emplace(daemon_username, daemon_password);

      // verify cert if \`use_ssl == true\`, otherwise autodetect if \`https\`
      // specified.
      const bool https = url.schema == "https";
      epee::net_utils::ssl_options_t options{
        !use_ssl ?
          (https ? epee::net_utils::ssl_support_t::e_ssl_support_autodetect : epee::net_utils::ssl_support_t::e_ssl_support_disabled) :
            epee::net_utils::ssl_support_t::e_ssl_support_enabled
      };

      if (!url.port)
      {
        if ((use_ssl || https))
          url.port = 443;
        else
          url.port = 80;
      }

      // Configure SSL certificate verification
      if (options.support != epee::net_utils::ssl_support_t::e_ssl_support_disabled)
      {
        bool ca_file_valid = !ca_file_path_.empty() && std::filesystem::exists(ca_file_path_);
        
        if (ca_file_valid) {
          try {
            options = epee::net_utils::ssl_options_t(
              std::vector<std::vector<std::uint8_t>>{},
              ca_file_path_
            );
            options.verification = epee::net_utils::ssl_verification_t::user_ca;
          } catch (const std::exception& e) {
            options.verification = epee::net_utils::ssl_verification_t::system_ca;
          }
        } else {
          options.verification = epee::net_utils::ssl_verification_t::system_ca;
        }
      }

      const boost::unique_lock<boost::mutex> lock{data_->sync};
      data_->client.set_server(std::move(url.host), std::to_string(url.port), std::move(login), std::move(options));
      data_->passed_login = false;
      data_->client_prefix = std::move(url.uri);
    }
    catch (const std::exception& e)
    {
      set_critical(e);
      return false;
    }

    return true;
  }`,
        `  bool wallet::init(const std::string &daemon_address, uint64_t limit, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool light_wallet, const std::string &proxy_address)
  {
    epee::net_utils::http::url_content url{};
    const bool https =
      epee::net_utils::parse_url(daemon_address, url) &&
      url.schema == "https";
    epee::net_utils::ssl_options_t options{
      use_ssl
        ? epee::net_utils::ssl_support_t::e_ssl_support_enabled
        : (https
            ? epee::net_utils::ssl_support_t::e_ssl_support_autodetect
            : epee::net_utils::ssl_support_t::e_ssl_support_disabled)
    };
    return initWithTls(daemon_address, limit, daemon_username, daemon_password,
                       light_wallet, proxy_address, std::move(options));
  }

  bool wallet::initWithTls(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool light_wallet, const std::string &proxy_address, epee::net_utils::ssl_options_t options)
  {
    if (!light_wallet)
      throw std::invalid_argument{"Only light_wallets are supported with this instance"};
    try
    {
      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(daemon_address, url))
        throw std::runtime_error{"Invalid LWS URL: " + daemon_address};
      if (!proxy_address.empty() && !setProxy(proxy_address))
        return false;
      boost::optional<epee::net_utils::http::login> login;
      if (!daemon_username.empty() || !daemon_password.empty())
        login.emplace(daemon_username, daemon_password);
      if (!url.port)
        url.port = options.support == epee::net_utils::ssl_support_t::e_ssl_support_disabled ? 80 : 443;
      // The caller's ssl_options already carry the exact per-node policy
      // (bundled CA, custom CA, pinned certificate, fingerprint, or none), so
      // upstream's ca_file_path_ override is deliberately not applied here.
      const boost::unique_lock<boost::mutex> lock{data_->sync};
      data_->client.set_server(std::move(url.host), std::to_string(url.port),
                               std::move(login), std::move(options));
      data_->passed_login = false;
      data_->client_prefix = std::move(url.uri);
    }
    catch (const std::exception& e)
    {
      set_critical(e);
      return false;
    }
    return true;
  }`
      )
      .replace(
        `  std::size_t wallet::numSubaddresses(const std::uint32_t accountIndex) const
  {
    static_assert(std::numeric_limits<std::uint32_t>::max() <= std::numeric_limits<std::size_t>::max());
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (accountIndex < data_->primary.subaccounts.size())
      return std::size_t(data_->primary.subaccounts.at(accountIndex).last) + 1;
    set_critical(std::runtime_error{"numSubaddresses failed, " + std::to_string(accountIndex) + " does not exist"});
    return 0;
  }`,
        `  std::size_t wallet::numSubaddresses(const std::uint32_t accountIndex) const
  {
    static_assert(std::numeric_limits<std::uint32_t>::max() <= std::numeric_limits<std::size_t>::max());
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (accountIndex < data_->primary.subaccounts.size())
      return std::size_t(data_->primary.subaccounts.at(accountIndex).last) + 1;
    set_critical(std::runtime_error{"numSubaddresses failed, " + std::to_string(accountIndex) + " does not exist"});
    return 0;
  }

  std::uint32_t wallet::nextUnusedSubaddressIndex(const std::uint32_t accountIndex) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    bool found = false;
    std::uint32_t max_used = 0;

    for (const auto& entry : data_->primary.txes)
    {
      const auto& tx = *entry.second;
      if (tx.direction != Monero::TransactionInfo::Direction_In)
        continue;

      for (const auto& receive : tx.receives)
      {
        const auto& recipient = receive.second.recipient;
        if (recipient.maj_i == accountIndex &&
            (!found || recipient.min_i > max_used))
        {
          found = true;
          max_used = recipient.min_i;
        }
      }
    }

    if (!found)
      return 0;
    if (max_used == std::numeric_limits<std::uint32_t>::max())
      throw std::runtime_error{"Subaddress index overflow"};
    return max_used + 1;
  }`
      )
    if (
      !patchedLwsfWalletCpp.includes('wallet::initWithTls') ||
      !patchedLwsfWalletCpp.includes(
        'epee::net_utils::parse_url(daemon_address, url) &&'
      )
    ) {
      throw new Error('lwsf wallet.cpp TLS patch anchor did not match')
    }
    await writeFile(lwsfWalletCppPath, patchedLwsfWalletCpp, 'utf8')

    const lwsfWalletManagerPath = join(build.cwd, 'src/wallet_manager.cpp')
    const lwsfWalletManager = await readFile(lwsfWalletManagerPath, 'utf8')
    const patchedLwsfWalletManager = lwsfWalletManager
      .replace(
        `        client_.set_server(std::move(url.host), std::to_string(url.port), boost::none, std::move(options));
      }

    //! returns whether the daemon can be reached`,
        `        client_.set_server(std::move(url.host), std::to_string(url.port), boost::none, std::move(options));
      }

      void setDaemonAddressWithTls(
        const std::string &address,
        epee::net_utils::ssl_options_t options,
        const std::string &proxy_address) override
      {
        epee::net_utils::http::url_content url{};
        if (!epee::net_utils::parse_url(address, url))
          throw std::runtime_error{"Invalid LWS URL: " + address};
        if (!url.m_uri_content.m_path.empty())
          throw std::runtime_error{"LWS URL contains path (unsupported)"};
        if (proxy_address.empty())
          client_.set_connector(epee::net_utils::direct_connect{});
        else
        {
          auto endpoint = net::get_tcp_endpoint(proxy_address);
          if (!endpoint)
            throw std::runtime_error{"Invalid SOCKS proxy address"};
          client_.set_connector(net::socks::connector{std::move(*endpoint)});
        }
        if (!url.port)
          url.port = options.support == epee::net_utils::ssl_support_t::e_ssl_support_disabled ? 80 : 443;
        client_.set_server(std::move(url.host), std::to_string(url.port),
                           boost::none, std::move(options));
      }

    //! returns whether the daemon can be reached`
      )
      .replace(
        `      bool connected(uint32_t *version = NULL) override
      {
        if (version)
          *version = 0;
        return client_.is_connected();
      }`,
        `      bool connected(uint32_t *version = NULL) override
      {
        if (version)
          *version = 0;
        (void)get_daemon_status();
        return error_.empty();
      }`
      )
    if (
      !patchedLwsfWalletManager.includes('setDaemonAddressWithTls') ||
      !patchedLwsfWalletManager.includes('(void)get_daemon_status();')
    ) {
      throw new Error('lwsf wallet_manager.cpp TLS patch anchor did not match')
    }
    await writeFile(lwsfWalletManagerPath, patchedLwsfWalletManager, 'utf8')

    build.exportEnv({
      PKG_CONFIG_PATH: join(prefixPath, '/lib/pkgconfig')
    })

    // Works for Android:
    await build.exec('cmake', [
      // Source directory:
      `-S${build.cwd}`,
      // Build directory:
      `-B${join(build.cwd, 'cmake')}`,
      // Build options:
      `-DCMAKE_BUILD_TYPE=Release`,
      `-DCMAKE_CXX_FLAGS=-DLWSF_MASTER_ENABLE`,
      `-DCMAKE_C_FLAGS=-D_DARWIN_C_SOURCE`,
      `-DCMAKE_FIND_ROOT_PATH=${prefixPath};${platform.sysroot}"`,
      `-DCMAKE_INSTALL_PREFIX=${prefixPath}`,
      `-DCMAKE_PREFIX_PATH=${prefixPath}`,
      `-DMONERO_SOURCE_DIR=${join(build.basePath, 'monero')}`,
      `-DSTATIC=true`,
      `-DUSE_DEVICE_TREZOR=OFF`,
      ...platform.cmakeFlags
    ])
    await build.exec('cmake', [
      '--build',
      join(build.cwd, 'cmake'),
      '--config',
      'Release',
      '--target',
      'lwsf-api'
    ])

    build.log('done')
  }
})
