/**
 * One shared live connection (`/ws/e2ee`) for the whole app.
 *
 * The chat screen and the notification system both listen to the same connection, so the app never
 * opens two sockets at once. The connection opens with the first listener and closes with the last.
 */
import { connectE2EEWebSocket } from './e2eeApi.ts';

export type E2EERealtimeEvent = Record<string, any>;
type Listener = (evt: E2EERealtimeEvent) => void;

const listeners = new Set<Listener>();
let socket: { close: () => void } | null = null;
let live = false;

/** True while the live connection is open and signed in (server sent 'authenticated'). */
export function isE2EERealtimeLive(): boolean {
  return live;
}

function dispatch(evt: E2EERealtimeEvent) {
  if (evt.type === 'authenticated') live = true;
  else if (evt.type === 'ws_closed') live = false;
  // An admin gave or took back free access: refresh membership, groups and the Payments tab now.
  if (evt.type === 'access_changed' && typeof window !== 'undefined') {
    window.dispatchEvent(new Event('zyphra:groups-changed'));
  }
  for (const fn of Array.from(listeners)) {
    try {
      fn(evt);
    } catch (err) {
      console.warn('[zyphra] realtime listener failed', err);
    }
  }
}

export function subscribeE2EERealtime(listener: Listener): () => void {
  listeners.add(listener);
  if (!socket) socket = connectE2EEWebSocket(dispatch);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && socket) {
      socket.close();
      socket = null;
      live = false;
    }
  };
}