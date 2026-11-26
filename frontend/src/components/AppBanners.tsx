import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CalendarClock, Info, X } from 'lucide-react';
import { fetchAnnouncement, fetchRenewalReminders, type PlatformAnnouncement, type RenewalReminder } from '../services/platformApi';
import { pushReminder } from '../services/notificationStore';
import './chat/chatExtras.css';

/**
 * Banners at the top of the app:
 * 1. The admin's announcement for everyone ("Maintenance Sunday 10 pm"). A member can close it; a new
 *    text from the admin shows again.
 * 2. Renewal reminder: membership / paid-group access ending within 7 days, within a day, or ended.
 *    Each stage also goes to the notification bell once. Members sign in with a wallet and have no
 *    email, so these in-app reminders are the only channel.
 */

const DISMISSED_ANN = 'zyphra_banner_dismissed';
const DISMISSED_REM = 'zyphra_reminder_dismissed';

function readList(key: string): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(key) || '[]');
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function addToList(key: string, value: string): string[] {
  const next = [...readList(key).filter((x) => x !== value), value].slice(-30);
  try {
    localStorage.setItem(key, JSON.stringify(next));
  } catch {
    /* storage unavailable */
  }
  return next;
}

function whenText(iso: string): string {
  return new Date(iso).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
}

export function reminderText(r: RenewalReminder, now = Date.now()): string {
  const what = r.scope_type === 'platform' ? (r.free_access ? 'Your free membership' : 'Your membership') : `Your access to "${r.name}"`;
  const ms = Date.parse(r.expires_at) - now;
  if (r.stage === 'expired') return `${what} ended on ${whenText(r.expires_at)}. Renew to keep chatting.`;
  if (r.stage === '1d') {
    const hours = Math.max(1, Math.round(ms / 3_600_000));
    return `${what} ends in ${hours} hour${hours === 1 ? '' : 's'}. Renew now so nothing stops.`;
  }
  const days = Math.max(1, Math.ceil(ms / 86_400_000));
  return `${what} ends in ${days} day${days === 1 ? '' : 's'} (${whenText(r.expires_at)}).`;
}

export const AppBanners: React.FC<{ signedIn: boolean; onOpenPayments: () => void }> = ({ signedIn, onOpenPayments }) => {
  const [announcement, setAnnouncement] = useState<PlatformAnnouncement | null>(null);
  const [dismissedAnn, setDismissedAnn] = useState<string[]>(() => readList(DISMISSED_ANN));
  const [reminders, setReminders] = useState<RenewalReminder[]>([]);
  const [dismissedRem, setDismissedRem] = useState<string[]>(() => readList(DISMISSED_REM));

  const loadAnnouncement = useCallback(() => {
    fetchAnnouncement()
      .then((r) => setAnnouncement(r.announcement))
      .catch(() => { });
  }, []);

  const loadReminders = useCallback(() => {
    if (!signedIn) {
      setReminders([]);
      return;
    }
    fetchRenewalReminders()
      .then((r) => {
        setReminders(r.reminders);
        for (const rem of r.reminders) {
          pushReminder({
            key: rem.key,
            title: rem.stage === 'expired' ? 'Access ended' : 'Renewal reminder',
            body: reminderText(rem),
          });
        }
      })
      .catch(() => { });
  }, [signedIn]);

  useEffect(() => {
    loadAnnouncement();
    loadReminders();
    const a = window.setInterval(loadAnnouncement, 3 * 60_000);
    const r = window.setInterval(loadReminders, 30 * 60_000);
    const onFocus = () => {
      loadAnnouncement();
      loadReminders();
    };
    window.addEventListener('focus', onFocus);
    // A payment or renewal elsewhere in the app refreshes the reminder straight away.
    window.addEventListener('zyphra:groups-changed', loadReminders);
    return () => {
      window.clearInterval(a);
      window.clearInterval(r);
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('zyphra:groups-changed', loadReminders);
    };
  }, [loadAnnouncement, loadReminders]);

  const reminder = reminders.find((r) => !dismissedRem.includes(r.key)) || null;
  const showAnn = announcement && !dismissedAnn.includes(announcement.id);
  if (!showAnn && !reminder) return null;

  return (
    <div>
      {showAnn && announcement && (
        <div className={`app-banner ${announcement.level === 'warning' ? 'is-warning' : ''}`} role="status">
          {announcement.level === 'warning' ? <AlertTriangle size={16} aria-hidden="true" /> : <Info size={16} aria-hidden="true" />}
          <span className="txt">{announcement.text}</span>
          <button type="button" aria-label="Close this announcement" onClick={() => setDismissedAnn(addToList(DISMISSED_ANN, announcement.id))}>
            <X size={15} />
          </button>
        </div>
      )}
      {reminder && (
        <div className={`app-banner ${reminder.stage === 'expired' ? 'is-danger' : reminder.stage === '1d' ? 'is-warning' : ''}`} role="status">
          <CalendarClock size={16} aria-hidden="true" />
          <span className="txt">{reminderText(reminder)}</span>
          <button type="button" className="act" onClick={onOpenPayments}>
            Renew
          </button>
          <button type="button" aria-label="Close this reminder" onClick={() => setDismissedRem(addToList(DISMISSED_REM, reminder.key))}>
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
};
