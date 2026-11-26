/** Scrolls to a message by id and briefly highlights it. Returns false when it is not loaded. */
export function jumpToMessage(messageId: string): boolean {
  if (!messageId || typeof document === 'undefined') return false;
  const safe = typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(messageId) : messageId.replace(/"/g, '');
  const row = document.querySelector<HTMLElement>(`[data-msg-id="${safe}"]`);
  if (!row) return false;
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  row.scrollIntoView({ block: 'center', behavior: reduce ? 'auto' : 'smooth' });
  row.classList.remove('ig-flash');
  void row.offsetWidth;
  row.classList.add('ig-flash');
  setTimeout(() => row.classList.remove('ig-flash'), 1600);
  return true;
}
