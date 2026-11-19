import { useEffect, useRef } from 'react';

/**
 * The Zyphra "1 in 10,000" field: a 100 x 100 grid of points with exactly one lit.
 *
 * - animate = true  -> plays the intro (the point lights, a pulse reveals the field)
 * - animate = false -> draws the settled field once (used on the welcome gate)
 *
 * The point colour comes from the CSS `color` of the canvas, so it works on the always-black
 * splash and on the theme-aware welcome gate (it redraws when the theme changes).
 */

export const GRID = 100; // 100 x 100 = 10,000 points
const LIT_X = 62; // the one lit point (deliberately off-centre)
const LIT_Y = 37;

interface DotFieldProps {
  animate?: boolean;
  className?: string;
}

export default function DotField({ animate = false, className }: DotFieldProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx) return;

    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const still = !animate || Boolean(reduced);

    let raf = 0;
    let cssSize = 0;
    let dpr = 1;
    let color = '#ffffff';
    let staticLayer: HTMLCanvasElement | null = null;
    const startedAt = performance.now();

    const setup = () => {
      cssSize = canvas.clientWidth;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(cssSize * dpr);
      canvas.height = Math.round(cssSize * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      color = getComputedStyle(canvas).color || '#ffffff';
      staticLayer = null;
    };

    // Dim points, revealed up to pulse radius `radius` (in grid cells).
    const drawField = (c: CanvasRenderingContext2D, radius: number) => {
      const cell = cssSize / GRID;
      const dot = Math.max(1.2, cell * 0.56);
      const inset = (cell - dot) / 2;
      c.fillStyle = color;
      for (let y = 0; y < GRID; y++) {
        for (let x = 0; x < GRID; x++) {
          if (x === LIT_X && y === LIT_Y) continue;
          const edge = radius - Math.hypot(x - LIT_X, y - LIT_Y);
          if (edge <= 0) continue;
          const settled = Math.min(1, edge / 8);
          const crest = 0.7 * Math.exp(-(((edge - 2) / 2.5) ** 2)); // bright leading edge of the pulse
          c.globalAlpha = Math.min(1, 0.34 * settled + crest);
          c.fillRect(x * cell + inset, y * cell + inset, dot, dot);
        }
      }
      c.globalAlpha = 1;
    };

    const drawLit = (t: number) => {
      const cell = cssSize / GRID;
      const appear = Math.min(1, Math.max(0, (t - 300) / 350));
      if (appear <= 0) return;
      const pulse = still ? 1 : 0.88 + 0.12 * Math.sin(t / 240);
      const size = cell * 2.6 * (0.6 + 0.4 * appear) * pulse;
      const cx = (LIT_X + 0.5) * cell;
      const cy = (LIT_Y + 0.5) * cell;
      ctx.save();
      ctx.globalAlpha = appear;
      ctx.shadowColor = color;
      ctx.shadowBlur = cell * 9 * pulse;
      ctx.fillStyle = color;
      ctx.fillRect(cx - size / 2, cy - size / 2, size, size);
      ctx.restore();
    };

    const frame = (now: number) => {
      // The canvas can be detached a moment before React cancels this loop.
      if (!canvas.isConnected) return;
      if (canvas.clientWidth === 0) {
        if (!still) raf = requestAnimationFrame(frame);
        return;
      }
      if (canvas.clientWidth !== cssSize) setup();
      const t = still ? 99999 : now - startedAt;
      ctx.clearRect(0, 0, cssSize, cssSize);

      const radius = Math.max(0, ((t - 500) / 1000) * 70); // pulse speed: 70 cells / second
      if (radius >= 140) {
        // Pulse has passed everywhere: render the field once, then just blit it.
        if (!staticLayer) {
          staticLayer = document.createElement('canvas');
          staticLayer.width = canvas.width;
          staticLayer.height = canvas.height;
          const sctx = staticLayer.getContext('2d');
          if (sctx) {
            sctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            drawField(sctx, 999);
          }
        }
        ctx.drawImage(staticLayer, 0, 0, cssSize, cssSize);
      } else {
        drawField(ctx, radius);
      }
      drawLit(t);

      if (!still) raf = requestAnimationFrame(frame);
    };

    const redrawIfStill = () => {
      setup();
      if (still) frame(performance.now());
    };

    setup();
    if (still) frame(performance.now());
    else raf = requestAnimationFrame(frame);

    // Still mode has no loop, so redraw on resize and on theme change.
    let resizeObserver: ResizeObserver | null = null;
    let themeObserver: MutationObserver | null = null;
    if (still) {
      resizeObserver = new ResizeObserver(redrawIfStill);
      resizeObserver.observe(canvas);
      themeObserver = new MutationObserver(redrawIfStill);
      themeObserver.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['data-theme'],
      });
    }

    return () => {
      cancelAnimationFrame(raf);
      resizeObserver?.disconnect();
      themeObserver?.disconnect();
    };
  }, [animate]);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
