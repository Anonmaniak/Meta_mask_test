import React, { useEffect, useRef, useState } from 'react';
import {
  AtSign,
  CalendarClock, Bell, MessageSquare, Users, UserPlus, X
} from 'lucide-react';
import {
  useNotifications,
  markAllNotificationsSeen,
  markEverythingRead,
  setNotificationPrefs,
  enableDesktopNotifications,
  openNotification,
  dismissToast,
  type NotificationItem,
} from '../services/notificationStore';
import './notifications.css';

function timeAgo(at: number): string {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 45) return 'Just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  return new Date(at).toLocaleDateString();
}

function ItemIcon({ kind }: { kind: NotificationItem['kind'] }) {
  if (kind === 'group') return <Users size={16} />;
  if (kind === 'invite') return <UserPlus size={16} />;
  if (kind === 'mention') return <AtSign size={16} />;
  if (kind === 'reminder') return <CalendarClock size={16} />;
  return <MessageSquare size={16} />;
}

/** Bell in the header: unread count, recent notifications, and notification settings. */
export const NotificationBell: React.FC = () => {
  const n = useNotifications();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const badge = n.totalUnread + n.items.filter((i) => i.kind === 'invite' && !i.read).length;

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const desktopOn = n.prefs.desktop && n.permission === 'granted';

  return (
    <div className="notify-wrap" ref={wrapRef}>
      <button
        type="button"
        className={`theme-toggle-btn notify-bell ${badge > 0 ? 'has-unread' : ''}`}
        onClick={() => {
          setOpen((v) => !v);
          if (!open) markAllNotificationsSeen();
        }}
        title="Notifications"
        aria-label={badge > 0 ? `Notifications, ${badge} unread` : 'Notifications'}
        aria-expanded={open}
      >
        <Bell size={17} />
        {badge > 0 && <span className="notify-count">{badge > 99 ? '99+' : badge}</span>}
      </button>

      {open && (
        <div className="notify-panel" role="dialog" aria-label="Notifications">
          <div className="notify-panel-head">
            <h3>Notifications</h3>
            <button
              type="button"
              className="notify-link"
              disabled={n.totalUnread === 0 && n.unseenItems === 0 && !n.items.some((i) => !i.read)}
              onClick={() => markEverythingRead()}
            >
              Mark all as read
            </button>
          </div>

          <div className="notify-list">
            {n.items.length === 0 ? (
              <div className="notify-empty">
                {n.totalUnread > 0
                  ? `You have ${n.totalUnread} unread ${n.totalUnread === 1 ? 'message' : 'messages'}. Open Messages to read them.`
                  : 'No new notifications.'}
              </div>
            ) : (
              n.items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={`notify-item ${item.read ? '' : 'is-unread'}`}
                  onClick={() => {
                    openNotification(item);
                    setOpen(false);
                  }}
                >
                  <span className="notify-item-icon">
                    <ItemIcon kind={item.kind} />
                  </span>
                  <span className="notify-item-text">
                    <span className="notify-item-title">{item.title}</span>
                    <span className="notify-item-body">{item.body}</span>
                    <span className="notify-item-time">{timeAgo(item.at)}</span>
                  </span>
                </button>
              ))
            )}
          </div>

          <div className="notify-settings">
            <label className="notify-setting">
              <span>Sound for new messages</span>
              <input
                type="checkbox"
                checked={n.prefs.sound}
                onChange={(e) => setNotificationPrefs({ sound: e.target.checked })}
              />
            </label>
            <div className="notify-setting">
              <span>
                Notify me when Zyphra is in the background
                <small>
                  {n.permission === 'unsupported'
                    ? 'This browser does not support notifications.'
                    : n.permission === 'denied'
                      ? 'Blocked in your browser. Allow notifications for this site in the browser settings.'
                      : 'Shows who wrote, never the message text.'}
                </small>
              </span>
              {n.permission === 'granted' ? (
                <input
                  type="checkbox"
                  checked={desktopOn}
                  onChange={(e) => setNotificationPrefs({ desktop: e.target.checked })}
                  aria-label="Notify me when Zyphra is in the background"
                />
              ) : n.permission === 'default' ? (
                <button type="button" className="btn-outline" style={{ padding: '4px 10px', fontSize: '0.84rem' }} onClick={() => void enableDesktopNotifications()}>
                  Turn on
                </button>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

/** Small pop-up when a message arrives while you are somewhere else in the app. */
export const NotificationToast: React.FC = () => {
  const { toast } = useNotifications();

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => dismissToast(), 6000);
    return () => clearTimeout(t);
  }, [toast]);

  if (!toast) return null;
  return (
    <div className="notify-toast" role="status" aria-live="polite">
      <button type="button" className="notify-toast-open" onClick={() => openNotification(toast)}>
        <span className="notify-item-icon">
          <ItemIcon kind={toast.kind} />
        </span>
        <span className="notify-item-text">
          <span className="notify-item-title">{toast.title}</span>
          <span className="notify-item-body">{toast.body}</span>
        </span>
      </button>
      <button type="button" className="theme-toggle-btn" style={{ width: 30, height: 30 }} onClick={dismissToast} aria-label="Dismiss">
        <X size={14} />
      </button>
    </div>
  );
};