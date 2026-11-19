import type { NetworkInfo } from '../types';

declare global {
  interface Window {
    ethereum?: any;
  }
}

export const SUPPORTED_NETWORKS: Record<string, NetworkInfo> = {
  '0x1': {
    chainIdHex: '0x1',
    chainIdNum: 1,
    name: 'Ethereum Mainnet',
    shortName: 'Mainnet',
    symbol: 'ETH',
    explorerBase: 'https://etherscan.io/address/',
  },
  '0xaa36a7': {
    chainIdHex: '0xaa36a7',
    chainIdNum: 11155111,
    name: 'Sepolia Testnet',
    shortName: 'Sepolia',
    symbol: 'SepoliaETH',
    explorerBase: 'https://sepolia.etherscan.io/address/',
  },
};

export function isMetaMaskInstalled(): boolean {
  return typeof window !== 'undefined' && Boolean(window.ethereum);
}

export function validateEthAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address.trim());
}

export function formatAddress(address: string, chars = 4): string {
  if (!address) return '';
  if (address.length <= chars * 2 + 2) return address;
  return `${address.slice(0, chars + 2)}...${address.slice(-chars)}`;
}

export function formatEth(wei: bigint | string | number, decimals = 6): string {
  try {
    const b = BigInt(wei.toString());
    const whole = b / 1000000000000000000n;
    const rem = b % 1000000000000000000n;
    const fracStr = rem.toString().padStart(18, '0').slice(0, decimals);
    return decimals > 0 ? `${whole.toString()}.${fracStr}` : whole.toString();
  } catch {
    return '0.000000';
  }
}

export async function requestAccounts(): Promise<string[]> {
  if (!window.ethereum) throw new Error('MetaMask is not installed');
  const accounts: string[] = await window.ethereum.request({
    method: 'eth_requestAccounts',
  });
  return accounts;
}

export async function getChainId(): Promise<string> {
  if (!window.ethereum) throw new Error('MetaMask is not installed');
  return window.ethereum.request({ method: 'eth_chainId' });
}

export async function getBalance(address: string): Promise<bigint> {
  if (!window.ethereum || !address) return 0n;
  const hexBalance: string = await window.ethereum.request({
    method: 'eth_getBalance',
    params: [address, 'latest'],
  });
  return BigInt(hexBalance);
}

export async function switchNetwork(chainIdHex: string): Promise<void> {
  if (!window.ethereum) throw new Error('MetaMask is not installed');
  try {
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: chainIdHex }],
    });
  } catch (error: any) {
    if (error.code === 4902 && chainIdHex === '0xaa36a7') {
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [
          {
            chainId: '0xaa36a7',
            chainName: 'Sepolia Testnet',
            nativeCurrency: { name: 'Sepolia ETH', symbol: 'ETH', decimals: 18 },
            rpcUrls: ['https://rpc.sepolia.org'],
            blockExplorerUrls: ['https://sepolia.etherscan.io'],
          },
        ],
      });
    } else {
      throw error;
    }
  }
}
