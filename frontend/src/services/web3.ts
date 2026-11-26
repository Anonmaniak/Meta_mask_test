declare global {
  interface Window {
    ethereum?: any;
  }
}

export function isMetaMaskInstalled(): boolean {
  return typeof window !== 'undefined' && Boolean(window.ethereum);
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
