// Shared in-memory transaction storage
// Both transaction.js and verify.js import this to share the same array

let transactions = [];

module.exports = {
  getTransactions: () => transactions,
  addTransaction: (tx) => {
    transactions.unshift(tx);
    // Keep only last 50 transactions
    if (transactions.length > 50) {
      transactions = transactions.slice(0, 50);
    }
    return tx;
  },
  findTransaction: (criteria) => {
    if (typeof criteria === 'function') {
      return transactions.find(criteria);
    }
    if (criteria.id) {
      return transactions.find(tx => tx.id === criteria.id);
    }
    if (criteria.escrowTxHash) {
      return transactions.find(tx => tx.escrowTxHash === criteria.escrowTxHash);
    }
    return null;
  },
  removeTransaction: (id) => {
    const index = transactions.findIndex(tx => tx.id === id);
    if (index > -1) {
      transactions.splice(index, 1);
      return true;
    }
    return false;
  },
  updateTransaction: (id, updates) => {
    const tx = transactions.find(tx => tx.id === id);
    if (tx) {
      Object.assign(tx, updates);
      return tx;
    }
    return null;
  }
};
