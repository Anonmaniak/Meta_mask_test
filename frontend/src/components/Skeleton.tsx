import React from 'react';

interface SkeletonBoxProps {
  width?: string | number;
  height?: string | number;
  radius?: string | number;
  style?: React.CSSProperties;
}

/** Theme-aware shimmer placeholder block. */
export const SkeletonBox: React.FC<SkeletonBoxProps> = ({
  width = '100%',
  height = 14,
  radius = 8,
  style,
}) => (
  <span
    aria-hidden="true"
    className="skeleton-box"
    style={{ width, height, borderRadius: radius, ...style }}
  />
);

/** Skeleton for list items (directory, groups, support threads, activity rows). */
export const ListRowsSkeleton: React.FC<{
  count?: number;
  showButton?: boolean;
  compact?: boolean;
}> = ({ count = 4, showButton = false, compact = false }) => (
  <div
    role="status"
    aria-label="Loading"
    style={{ display: 'flex', flexDirection: 'column', gap: compact ? 8 : 10 }}
  >
    {Array.from({ length: count }).map((_, idx) => (
      <div
        key={idx}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          padding: compact ? '10px 12px' : '12px 16px',
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 12,
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1, minWidth: 0 }}>
          <SkeletonBox width={`${42 + ((idx * 17) % 30)}%`} height={14} />
          <SkeletonBox width={`${60 + ((idx * 13) % 28)}%`} height={11} />
        </div>
        {showButton && <SkeletonBox width={88} height={32} radius={9999} />}
      </div>
    ))}
  </div>
);

/** Compact skeleton rows for the chat sidebar rails (Groups / Private chats). */
export const SidebarListSkeleton: React.FC<{ count?: number }> = ({ count = 3 }) => (
  <div
    role="status"
    aria-label="Loading conversations"
    style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: '2px 4px' }}
  >
    {Array.from({ length: count }).map((_, idx) => (
      <div
        key={idx}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '8px 10px',
          borderRadius: 10,
        }}
      >
        <SkeletonBox width={18} height={18} radius="50%" style={{ flexShrink: 0 }} />
        <SkeletonBox width={`${52 + ((idx * 19) % 34)}%`} height={13} />
      </div>
    ))}
  </div>
);

/** Skeleton for chat message streams (Open room, DMs, Groups, Support thread). */
export const ChatMessagesSkeleton: React.FC<{ count?: number }> = ({ count = 5 }) => (
  <div
    role="status"
    aria-label="Loading messages"
    style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '4px 0' }}
  >
    {Array.from({ length: count }).map((_, idx) => {
      const isRight = idx % 3 === 1;
      return (
        <div
          key={idx}
          style={{
            display: 'flex',
            flexDirection: isRight ? 'row-reverse' : 'row',
            alignItems: 'flex-start',
            gap: 12,
            maxWidth: '78%',
            alignSelf: isRight ? 'flex-end' : 'flex-start',
          }}
        >
          <SkeletonBox width={34} height={34} radius={10} style={{ flexShrink: 0 }} />
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 7,
              alignItems: isRight ? 'flex-end' : 'flex-start',
              minWidth: 160,
            }}
          >
            <SkeletonBox width={90} height={11} />
            <div
              style={{
                padding: '12px 14px',
                borderRadius: 14,
                border: '1px solid var(--border-subtle)',
                background: 'var(--bg-input)',
                display: 'flex',
                flexDirection: 'column',
                gap: 7,
                width: idx % 2 === 0 ? 250 : 190,
                maxWidth: '100%',
              }}
            >
              <SkeletonBox width="100%" height={13} />
              {idx % 2 === 0 && <SkeletonBox width="68%" height={13} />}
            </div>
          </div>
        </div>
      );
    })}
  </div>
);

/** Skeleton for pricing modals (PlatformAdmissionModal / PaidGroupAdmissionModal). */
export const PricingModalSkeleton: React.FC = () => (
  <div
    role="status"
    aria-label="Loading pricing"
    style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}
  >
    <div
      style={{
        border: '1px solid var(--border-subtle)',
        borderRadius: 20,
        padding: '1.3rem',
        background: 'var(--bg-input)',
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      <div className="plan-grid">
        <div
          style={{
            padding: '16px 18px',
            borderRadius: 16,
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: 10,
          }}
        >
          <SkeletonBox width="45%" height={13} />
          <SkeletonBox width="70%" height={26} />
        </div>
        <div
          style={{
            padding: '16px 18px',
            borderRadius: 16,
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: 10,
          }}
        >
          <SkeletonBox width="55%" height={13} />
          <SkeletonBox width="75%" height={26} />
        </div>
      </div>
      <SkeletonBox width="50%" height={13} />
      <SkeletonBox width="64%" height={34} />
      <SkeletonBox width="85%" height={12} />
    </div>
    <SkeletonBox width="100%" height={48} radius={9999} />
  </div>
);

/** Skeleton for the Membership / Payments tab while loading initial status. */
export const PaymentsViewSkeleton: React.FC = () => (
  <div
    role="status"
    aria-label="Loading membership"
    className="membership-grid"
    style={{
      display: 'grid',
      gridTemplateColumns: 'minmax(0, 440px) minmax(0, 1fr)',
      gap: 'clamp(24px, 4vw, 56px)',
      alignItems: 'start',
    }}
  >
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div
        style={{
          width: '100%',
          maxWidth: 440,
          aspectRatio: '1.586 / 1',
          borderRadius: 22,
          padding: '26px 28px',
          border: '1px solid var(--border-subtle)',
          background: 'var(--bg-card)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <SkeletonBox width={88} height={22} />
          <SkeletonBox width={42} height={42} radius="50%" />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <SkeletonBox width="56%" height={24} />
          <SkeletonBox width="40%" height={13} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <SkeletonBox width={68} height={11} />
            <SkeletonBox width={120} height={16} />
          </div>
          <SkeletonBox width={92} height={28} radius={9999} />
        </div>
      </div>
      <SkeletonBox width={180} height={42} radius={9999} />
    </div>

    <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <SkeletonBox width={160} height={24} />
        <ListRowsSkeleton count={2} showButton compact />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <SkeletonBox width={180} height={24} />
        <ListRowsSkeleton count={3} compact />
      </div>
    </div>
  </div>
);

/** Skeleton for the Admin Dashboard overview cards & panel before initial load completes. */
export const AdminDashboardSkeleton: React.FC = () => (
  <div
    role="status"
    aria-label="Loading admin overview"
    style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
  >
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
        gap: 14,
      }}
    >
      {Array.from({ length: 8 }).map((_, idx) => (
        <div key={idx} className="deck-card" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <SkeletonBox width="62%" height={13} />
          <SkeletonBox width="40%" height={32} />
        </div>
      ))}
    </div>
    <div className="deck-card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <SkeletonBox width="35%" height={20} />
      <ListRowsSkeleton count={4} showButton />
    </div>
  </div>
);

/** Skeleton shown during startup session verification when a stored session is resuming. */
export const AppResumeSkeleton: React.FC = () => (
  <div
    role="status"
    aria-label="Resuming session"
    className="console-workspace chat-workspace-mode"
  >
    <div className="chat-console-grid" style={{ padding: 0 }}>
      <div className="chat-channels-rail" style={{ padding: 18, gap: 14 }}>
        <SkeletonBox width="55%" height={24} />
        <SkeletonBox width="100%" height={42} radius={14} />
        <SidebarListSkeleton count={4} />
        <SidebarListSkeleton count={3} />
      </div>
      <div className="chat-viewport" style={{ padding: 24, gap: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <SkeletonBox width={220} height={22} />
          <SkeletonBox width={110} height={28} radius={9999} />
        </div>
        <ChatMessagesSkeleton count={5} />
      </div>
    </div>
  </div>
);
