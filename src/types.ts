export type NetworkType = 'MAINNET' | 'TESTNET' | 'STAGENET'

const networkTypeMap: Record<NetworkType, number> = {
  MAINNET: 0,
  TESTNET: 1,
  STAGENET: 2
}

export function networkTypeToIntString(type: NetworkType): string {
  return networkTypeMap[type]?.toString() ?? '0'
}

export type WalletBackend = 'lws' | 'monerod'

/**
 * TLS verification applied to one daemon connection.
 *
 * HTTPS defaults to bundled-ca when this is omitted. Lenient verification is
 * never selected implicitly.
 */
export type MoneroTlsConfig =
  | { mode: 'bundled-ca' }
  | { mode: 'fingerprint'; sha256: string }
  | { mode: 'certificate'; pem: string }
  | { mode: 'unverified' }
  | { mode: 'onion' }

/** Daemon endpoint and its connection-specific transport policy. */
export interface MoneroNodeConfig {
  address: string
  tls?: MoneroTlsConfig
  /** SOCKS proxy in host:port form. Required for native .onion resolution. */
  proxyAddress?: string
}

/** SHA-256 identity returned by discoverTlsPeerIdentity. */
export interface MoneroTlsPeerIdentity {
  sha256Fingerprint: string
}

export interface GeneratedWallet {
  mnemonic: string
  secretSpendKey: string
  publicSpendKey: string
}

/** Return type for seedAndKeysFromMnemonic. */
export interface DerivedKeys {
  address: string
  secretViewKey: string
  publicViewKey: string
  secretSpendKey: string
  publicSpendKey: string
}

/** Return type for getSubaddress / getNextSubaddress. */
export interface SubaddressInfo {
  address: string
  accountIndex: number
  addressIndex: number
}

/** Summary of a subaddress account. */
export interface MoneroAccountSummary {
  index: number
  label: string
  balance: string
  unlockedBalance: string
}

/** Return type for openWallet and getWalletStatus. */
export interface WalletStatus {
  syncedHeight: number
  networkHeight: number
  balance: string
  unlockedBalance: string
  /**
   * True once at least one server refresh has completed for this wallet. LWS
   * wallets seed syncedHeight == networkHeight from the stored scan height
   * until their first refresh, so heights alone cannot tell "caught up" from
   * "has not looked yet"; treat the wallet as synced/spendable only when this
   * is true.
   */
  refreshed: boolean
}

/** Wallet status scoped to one subaddress account. */
export interface AccountStatus extends WalletStatus {
  otherAccountsBalance: string
}

/** Transaction direction. */
export type TransactionDirection = 0 | 1

/** Single transaction info. */
export interface TransactionInfo {
  hash: string
  direction: TransactionDirection
  isPending: boolean
  isFailed: boolean
  isCoinbase: boolean
  amount: string
  fee: string
  blockHeight: number
  confirmations: number
  timestamp: number
  paymentId: string
  description: string
  label: string
  unlockTime: number
  subaddrAccount: number
  /**
   * Minor subaddress indices involved in this tx. Incoming transfers always
   * have exactly one; outgoing transfers may spend from several.
   */
  subaddrIndex: number[]
  txKey?: string // Only available for outgoing transactions we sent
}

/** Return type for getAllTransactions. */
export interface TransactionsPage {
  transactions: TransactionInfo[]
  totalCount: number
  page: number
  pageSize: number
}

/** Transaction priority levels. */
export type TransactionPriority = 0 | 1 | 2 | 3

/** Recipient for createTransaction. */
export interface Recipient {
  address: string
  amount: string // atomic units as string to handle uint64
}

/** Return type for createTransaction. */
export interface SignedTransaction {
  txid: string
  signedTxHex: string
  fee: string
}

/** Parsed Monero URI (parseUri result). */
export interface ParsedUri {
  address: string
  paymentId: string
  amount: string // atomic units as string
  txDescription: string
  recipientName: string
  unknownParameters: string[]
}

/** Params for encodeUri (make monero: URI). */
export interface EncodeUriParams {
  address: string
  paymentId?: string // empty or omit; use integrated address for payment id
  amount: string // atomic units as string
  txDescription?: string
  recipientName?: string
}

/** Wallet event names emitted by the native WalletListener. */
export type WalletEventName = 'pendingTransactionReceived' | 'nymFetchRequest'

/** Payload delivered by "MoneroWalletEvent" NativeEventEmitter events. */
export interface WalletEventData {
  walletId: string
  eventName: WalletEventName
  /**
   * JSON string whose shape depends on `eventName`:
   *   - pendingTransactionReceived: { txId: string, amount: number }
   *   - nymFetchRequest: { url, method, headers, bodyBase64 } — in this
   *     case `walletId` holds the nym requestId that must be passed to
   *     `resolveFetch` / `rejectFetch`.
   */
  data: string
}

/** Parsed payload for the `nymFetchRequest` wallet event. */
export interface NymFetchRequestPayload {
  url: string
  method: string
  headers: Record<string, string>
  bodyBase64: string
}
