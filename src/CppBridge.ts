'use strict'

import type {
  AccountStatus,
  DerivedKeys,
  EncodeUriParams,
  GeneratedWallet,
  MoneroAccountSummary,
  NetworkType,
  ParsedUri,
  Recipient,
  SignedTransaction,
  SubaddressInfo,
  TransactionPriority,
  TransactionsPage,
  WalletBackend,
  WalletStatus
} from './types'
import { networkTypeToIntString } from './types'

/**
 * The shape of the native C++ module exposed to React Native.
 *
 * You do not normally need this, but it is accessible as
 * `require('react-native').NativeModules.MoneroLwsfModule`.
 *
 * Pass this object to the `CppBridge` constructor to re-assemble the API.
 */
export interface NativeMoneroLwsfModule {
  readonly callMonero: (
    name: string,
    jsonArguments: string[]
  ) => Promise<string>

  readonly methodNames: string[]
  readonly documentDirectory: string
}

export class CppBridge {
  private readonly module: NativeMoneroLwsfModule

  constructor(moneroLwsfModule: NativeMoneroLwsfModule) {
    this.module = moneroLwsfModule
  }

  /**
   * Generate a new wallet's keys in memory (no disk I/O).
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @param language - Mnemonic language (e.g., "English")
   * @returns Generated wallet with mnemonic and spend keys
   */
  async generateWallet(
    nettype: NetworkType,
    language: string = 'English'
  ): Promise<GeneratedWallet> {
    const response = await this.module.callMonero('generateWallet', [
      networkTypeToIntString(nettype),
      language
    ])
    return JSON.parse(response) as GeneratedWallet
  }

  /**
   * Derive all keys from a mnemonic (no disk I/O).
   * @param mnemonic - The 25-word mnemonic seed
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @returns All four keys (view and spend, public and secret)
   */
  async seedAndKeysFromMnemonic(
    mnemonic: string,
    nettype: NetworkType
  ): Promise<DerivedKeys> {
    const response = await this.module.callMonero('seedAndKeysFromMnemonic', [
      mnemonic,
      networkTypeToIntString(nettype)
    ])
    return JSON.parse(response) as DerivedKeys
  }

  /**
   * Get the current network blockchain height from a daemon.
   * @param backend - Backend type ('lws' or 'monerod')
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @param daemonAddress - Daemon address to query
   * @returns Current blockchain height
   */
  async getNetworkBlockHeight(
    backend: WalletBackend,
    nettype: NetworkType,
    daemonAddress: string
  ): Promise<number> {
    const response = await this.module.callMonero('getNetworkBlockHeight', [
      backend,
      networkTypeToIntString(nettype),
      daemonAddress
    ])
    return parseInt(response, 10)
  }

  /**
   * Validate a Monero address.
   * @param address - The address to validate
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @returns true if valid, false otherwise
   */
  async isValidAddress(
    address: string,
    nettype: NetworkType
  ): Promise<boolean> {
    const response = await this.module.callMonero('isValidAddress', [
      address,
      networkTypeToIntString(nettype)
    ])
    return response === 'true'
  }

  /**
   * Open or create a wallet. If already open, returns current status.
   * If wallet exists on disk, opens it. Otherwise creates from mnemonic.
   * @param walletId - Unique identifier for the wallet
   * @param backend - Backend type ("lws" or "monerod")
   * @param mnemonic - The 25-word mnemonic seed
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @param restoreHeight - Block height to restore from
   * @param daemonAddress - Daemon address to connect to
   * @returns Current wallet status (heights and balances)
   */
  async openWallet(
    walletId: string,
    backend: WalletBackend,
    mnemonic: string,
    password: string,
    nettype: NetworkType,
    restoreHeight: number,
    daemonAddress: string
  ): Promise<WalletStatus> {
    const response = await this.module.callMonero('openWallet', [
      this.module.documentDirectory,
      walletId,
      backend,
      mnemonic,
      password,
      networkTypeToIntString(nettype),
      restoreHeight.toString(),
      daemonAddress
    ])
    return JSON.parse(response) as WalletStatus
  }

  /**
   * Get the current status of an open wallet.
   * @param walletId - Unique identifier for the wallet
   * @returns Current wallet status (heights and balances)
   */
  async getWalletStatus(walletId: string): Promise<WalletStatus> {
    const response = await this.module.callMonero('getWalletStatus', [walletId])
    return JSON.parse(response) as WalletStatus
  }

  /**
   * Get the receive address at a subaddress index, materializing rows up to
   * it so the wallet scans for payments to it. Monerod (wallet2) backend
   * only; the LWS backend does not implement subaddress rows.
   * @param walletId - Unique identifier for the wallet
   * @param accountIndex - Subaddress account (major) index
   * @param addressIndex - Subaddress (minor) index
   * @returns The address plus the indices it was derived from
   */
  async getSubaddress(
    walletId: string,
    accountIndex: number,
    addressIndex: number
  ): Promise<SubaddressInfo> {
    const response = await this.module.callMonero('getSubaddress', [
      walletId,
      String(accountIndex),
      String(addressIndex)
    ])
    return JSON.parse(response) as SubaddressInfo
  }

  /**
   * Next unused receive subaddress for an account: one past the highest
   * incoming tx minor index on that account, materialized natively.
   * Opening Receive twice without a payment returns the same address.
   */
  async getNextSubaddress(
    walletId: string,
    accountIndex: number = 0
  ): Promise<SubaddressInfo> {
    const response = await this.module.callMonero('getNextSubaddress', [
      walletId,
      String(accountIndex)
    ])
    return JSON.parse(response) as SubaddressInfo
  }

  /** Get summaries for all subaddress accounts in an open wallet. */
  async getAccounts(walletId: string): Promise<MoneroAccountSummary[]> {
    const response = await this.module.callMonero('getAccounts', [walletId])
    return JSON.parse(response) as MoneroAccountSummary[]
  }

  /** Create a subaddress account and return its index. */
  async createAccount(
    walletId: string,
    label: string
  ): Promise<{ index: number }> {
    const response = await this.module.callMonero('createAccount', [
      walletId,
      label
    ])
    return JSON.parse(response) as { index: number }
  }

  /** Get wallet status scoped to one subaddress account. */
  async getAccountStatus(
    walletId: string,
    accountIndex: number
  ): Promise<AccountStatus> {
    const response = await this.module.callMonero('getAccountStatus', [
      walletId,
      String(accountIndex)
    ])
    return JSON.parse(response) as AccountStatus
  }

  /** Create and retain a transaction spending from one subaddress account. */
  async createTransactionFromAccount(
    walletId: string,
    recipients: Recipient[],
    priority: TransactionPriority,
    accountIndex: number
  ): Promise<SignedTransaction> {
    const response = await this.module.callMonero(
      'createTransactionFromAccount',
      [
        walletId,
        recipients.map(r => r.address).join(','),
        recipients.map(r => r.amount).join(','),
        String(priority),
        String(accountIndex)
      ]
    )
    return JSON.parse(response) as SignedTransaction
  }

  /**
   * Close an open wallet.
   * @param walletId - Unique identifier for the wallet to close
   */
  async closeWallet(walletId: string): Promise<void> {
    await this.module.callMonero('closeWallet', [walletId])
  }

  /**
   * Delete a wallet's files from disk. Closes the wallet first if it's open.
   * @param walletId - Unique identifier for the wallet
   * @param backend - Backend type ('lws' or 'monerod')
   */
  async deleteWallet(walletId: string, backend: WalletBackend): Promise<void> {
    await this.module.callMonero('deleteWallet', [
      this.module.documentDirectory,
      walletId,
      backend
    ])
  }

  /**
   * Get all transactions with pagination.
   * @param walletId - Unique identifier for the wallet
   * @param page - Page number (0-indexed)
   * @param pageSize - Number of transactions per page
   * @param sort - Sort order: 'asc' (oldest first) or 'desc' (newest first), pending always at end
   * @returns Paginated transactions with metadata
   */
  async getAllTransactions(
    walletId: string,
    page: number,
    pageSize: number,
    sort: 'asc' | 'desc' = 'asc'
  ): Promise<TransactionsPage> {
    const response = await this.module.callMonero('getAllTransactions', [
      walletId,
      page.toString(),
      pageSize.toString(),
      sort
    ])
    return JSON.parse(response) as TransactionsPage
  }

  /**
   * Get not-yet-mined transactions with pagination. Same shape as
   * getAllTransactions, filtered to pending entries. Pending transactions sort
   * behind all confirmed ones in getAllTransactions, so a cursor-based scan of
   * confirmed history never reaches them; use this to read the pending set
   * directly. The set can include entries the backend reports as permanently
   * failed (isFailed: true); callers decide how to label those.
   * @param walletId - Unique identifier for the wallet
   * @param page - Page number (0-indexed)
   * @param pageSize - Number of transactions per page
   * @returns Paginated pending transactions with metadata
   */
  async getPendingTransactions(
    walletId: string,
    page: number,
    pageSize: number
  ): Promise<TransactionsPage> {
    const response = await this.module.callMonero('getPendingTransactions', [
      walletId,
      page.toString(),
      pageSize.toString()
    ])
    return JSON.parse(response) as TransactionsPage
  }

  /**
   * Create a transaction (supports multiple recipients).
   * The transaction is created and signed but not broadcast yet: it is retained
   * natively for a later broadcastTransaction call. At most 50 transactions are
   * retained per wallet (oldest disposed first; broadcasting an evicted one
   * reports that it must be recreated), and all are released when the wallet
   * closes. Payments the wallet would split into multiple on-chain
   * transactions are rejected, so a later broadcast is atomic.
   * @param walletId - Unique identifier for the wallet
   * @param recipients - Array of recipients with addresses and amounts (atomic units)
   * @param priority - Transaction priority (0=Default, 1=Low, 2=Medium, 3=High)
   * @returns SignedTransaction with txid, signedTxHex, and fee (atomic units)
   */
  async createTransaction(
    walletId: string,
    recipients: Recipient[],
    priority: TransactionPriority
  ): Promise<SignedTransaction> {
    const addresses = recipients.map(r => r.address).join(',')
    const amounts = recipients.map(r => r.amount).join(',')

    const response = await this.module.callMonero('createTransaction', [
      walletId,
      addresses,
      amounts,
      priority.toString(),
      this.module.documentDirectory
    ])
    return JSON.parse(response) as SignedTransaction
  }

  /**
   * Broadcast a previously created transaction. `signedTx` identifies the
   * natively retained transaction to broadcast.
   * @param walletId - Unique identifier for the wallet
   * @param signedTx - The signedTxHex returned by createTransaction
   * @returns "success"
   * @throws Error if the transaction is no longer retained (evicted, or the
   *   wallet was closed since creation) or the broadcast fails
   */
  async broadcastTransaction(
    walletId: string,
    signedTx: string
  ): Promise<string> {
    const response = await this.module.callMonero('broadcastTransaction', [
      walletId,
      signedTx,
      this.module.documentDirectory
    ])
    return response
  }

  /**
   * Parse a monero: URI into its components.
   * @param uri - The monero: URI to parse
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @returns Parsed URI components
   * @throws Error if URI is invalid
   */
  async parseUri(uri: string, nettype: NetworkType): Promise<ParsedUri> {
    const response = await this.module.callMonero('parseUri', [
      uri,
      networkTypeToIntString(nettype)
    ])
    const parsed = JSON.parse(response)
    if (typeof parsed === 'object' && 'error' in parsed) {
      throw new Error(parsed.error)
    }
    return parsed as ParsedUri
  }

  /**
   * Encode a monero: URI from components.
   * @param params - URI components (address, amount, etc.)
   * @param nettype - Network type (0=mainnet, 1=testnet, 2=stagenet)
   * @returns The encoded monero: URI
   * @throws Error if parameters are invalid
   */
  async encodeUri(
    params: EncodeUriParams,
    nettype: NetworkType
  ): Promise<string> {
    const response = await this.module.callMonero('encodeUri', [
      params.address,
      params.paymentId ?? '',
      params.amount,
      params.txDescription ?? '',
      params.recipientName ?? '',
      networkTypeToIntString(nettype)
    ])
    // Check for error response (JSON object with error field)
    if (response.startsWith('{')) {
      const parsed = JSON.parse(response)
      if (typeof parsed === 'object' && 'error' in parsed) {
        throw new Error(parsed.error)
      }
    }
    return response
  }

  /**
   * Set the API key for LWS (Light Wallet Server) requests.
   * Once set, the key will be included in all subsequent LWS HTTP POST requests
   * as an "api_key" field in the JSON body.
   * @param apiKey - The API key to include in LWS requests
   */
  async setLwsApiKey(apiKey: string): Promise<void> {
    await this.module.callMonero('setLwsApiKey', [apiKey])
  }

  /**
   * Enable or disable the Nym fetch interceptor.
   *
   * When enabled, all LWSF HTTP POST requests that the C++ wallet code
   * would have issued are redirected through the native event bridge. The
   * consumer must register a handler via `NativeEventEmitter` on the
   * "MoneroWalletEvent" event with `eventName === 'nymFetchRequest'` and
   * call `resolveFetch` / `rejectFetch` to complete the request.
   *
   * @param enabled - Whether to route HTTP through the JS fetch bridge
   * @param baseUrl - scheme://host[:port] of the LWSF server (must match
   *                  the daemon address used at openWallet time). Empty
   *                  when disabling.
   */
  async setNymEnabled(enabled: boolean, baseUrl: string): Promise<void> {
    await this.module.callMonero('setNymEnabled', [
      enabled ? 'true' : 'false',
      baseUrl
    ])
  }

  /**
   * Resolve a pending nym fetch request that was emitted as a
   * `nymFetchRequest` wallet event. Must be called with the same
   * `requestId` carried on the incoming event.
   *
   * @param requestId  - id forwarded via the native event
   * @param status     - HTTP status code returned from fetch
   * @param bodyBase64 - response body encoded as base64
   */
  async resolveFetch(
    requestId: string,
    status: number,
    bodyBase64: string
  ): Promise<void> {
    await this.module.callMonero('resolveFetch', [
      requestId,
      status.toString(),
      bodyBase64
    ])
  }

  /**
   * Reject a pending nym fetch request. The blocked C++ caller will
   * receive a runtime_error bubbled as an RPC failure.
   *
   * @param requestId    - id forwarded via the native event
   * @param errorMessage - human-readable error description
   */
  async rejectFetch(requestId: string, errorMessage: string): Promise<void> {
    await this.module.callMonero('rejectFetch', [requestId, errorMessage])
  }
}
