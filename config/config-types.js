// @flow

export type ConfigType = {
  network: NetworkConfigType,
  app: AppConfigType,
};

export type AppConfigType = {
  walletRefreshInterval: number,
  serverStatusRefreshInterval: number,
  logsBufferSize: number,
  logsFileSuffix: string,
  addressRequestSize: number,
  txsBodiesRequestSize: number,
  linearFee: {|
    constant: string,
    coefficient: string,
    certificate: string,
  |},
  genesisHash: string,
}

export type NetworkConfigType = {
  protocolMagic:
  633343913  // staging protocol magic
  | 764824073 // mainnet protocol magic
  | 1097911063, // testnet protocol magic
  backendUrl: string,
  websocketUrl: string,
  name: Network
};

export type Network = 'shelley-dev' | 'shelley-testnet' | 'development' | 'mainnet' | 'staging' | 'testnet' | 'test';
export const NetworkType: {
  SHELLEY_DEV: Network,
  SHELLEY_TESTNET: Network,
  DEVELOPMENT: Network,
  MAINNET: Network,
  STAGING: Network,
  TESTNET: Network,
  TEST: Network
} = {
  SHELLEY_DEV: 'shelley-dev',
  SHELLEY_TESTNET: 'shelley-testnet',
  DEVELOPMENT: 'development',
  MAINNET: 'mainnet',
  STAGING: 'staging',
  TESTNET: 'testnet',
  TEST: 'test',
};
