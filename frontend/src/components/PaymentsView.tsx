import React from 'react';
import { CreditCard } from 'lucide-react';

export const PaymentsView: React.FC = () => (
  <div
    className="deck-card"
    style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      textAlign: 'center',
      gap: '10px',
      padding: '56px 20px',
    }}
  >
    <CreditCard size={34} />
    <div className="deck-title" style={{ justifyContent: 'center' }}>
      Payments
    </div>
    <div style={{ fontSize: '1.05rem', fontWeight: 600 }}>Coming Soon</div>
    <div className="deck-subtitle">We are working on this. Stay tuned.</div>
  </div>
);

export default PaymentsView;

