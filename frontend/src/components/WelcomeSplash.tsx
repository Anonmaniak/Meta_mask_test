import { useEffect, useRef, useState } from 'react';
import DotField from './DotField';
import './WelcomeSplash.css';

/**
 * First-visit welcome animation for Zyphra.in
 *
 * "1% of 1%" is 1 in 10,000, so the animation is literally that: a 100 x 100 field of
 * 10,000 points, and exactly one of them lights up. A single pulse then travels out
 * from it and reveals the rest of the field.
 *
 * Shown ONCE per browser (first ever visit). Later visits and every refresh skip it.
 * The decision is made at module load (not in a component) so React StrictMode's
 * double render in development cannot consume the flag and hide the animation.
 */

// ---- Copy (change here) ----------------------------------------------------
const HEADLINE = 'Welcome to Zyphra.in';
const SUBLINE = 'For 1% of 1%';
const CAPTION = '1 in 10,000';

// ---- Behaviour ---------------------------------------------------------------
const STORAGE_KEY = 'zyphra_welcome_seen_v1';
const TOTAL_MS = 4800; // how long the splash stays before it fades out
const FADE_MS = 650; // fade-out duration
const REDUCED_MOTION_TOTAL_MS = 2400;

function decideShowOnThisLoad(): boolean {
  try {
    if (typeof window === 'undefined') return false;
    if (window.localStorage.getItem(STORAGE_KEY)) return false;
    window.localStorage.setItem(STORAGE_KEY, new Date().toISOString());
    return true;
  } catch {
    // Storage blocked (private mode etc.): we cannot remember a first visit, so do not nag.
    return false;
  }
}

const SHOW_ON_THIS_LOAD = decideShowOnThisLoad();

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
}

type Stage = 'in' | 'out' | 'done';

export default function WelcomeSplash() {
  const [stage, setStage] = useState<Stage>(SHOW_ON_THIS_LOAD ? 'in' : 'done');
  const dialogRef = useRef<HTMLDivElement>(null);
  const reduced = useRef(prefersReducedMotion());

  // Timeline: stay -> fade out -> unmount
  useEffect(() => {
    if (stage !== 'in') return;
    const stay = reduced.current ? REDUCED_MOTION_TOTAL_MS : TOTAL_MS;
    const t = window.setTimeout(() => setStage('out'), stay);
    return () => window.clearTimeout(t);
  }, [stage]);

  useEffect(() => {
    if (stage !== 'out') return;
    const t = window.setTimeout(() => setStage('done'), FADE_MS);
    return () => window.clearTimeout(t);
  }, [stage]);

  // Lock page scroll and focus the skip button while the splash is up
  useEffect(() => {
    if (stage === 'done') return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialogRef.current?.focus({ preventScroll: true });
    return () => {
      document.body.style.overflow = prev;
    };
  }, [stage === 'done']); // eslint-disable-line react-hooks/exhaustive-deps

  // Esc skips
  useEffect(() => {
    if (stage !== 'in') return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setStage('out');
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [stage]);

  if (stage === 'done') return null;

  return (
    <div
      ref={dialogRef}
      tabIndex={-1}
      className={`zws ${stage === 'out' ? 'zws--out' : ''}`}
      role="dialog"
      aria-modal="true"
      aria-label={`${HEADLINE}. ${SUBLINE}.`}
      onClick={() => setStage('out')}
    >
      <div className="zws__stage">
        <DotField animate className="zws__field" />
        <p className="zws__caption">{CAPTION}</p>
        <h1 className="zws__headline">
          <span className="zws__wipe">{HEADLINE}</span>
        </h1>
        <p className="zws__subline">{SUBLINE}</p>
      </div>

      <button
        type="button"
        className="zws__skip"
        onClick={(e) => {
          e.stopPropagation();
          setStage('out');
        }}
      >
        Skip
      </button>
    </div>
  );
}