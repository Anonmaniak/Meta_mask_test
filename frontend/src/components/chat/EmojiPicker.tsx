import React, { useEffect, useMemo, useRef, useState } from 'react';

/**
 * Emoji picker built in (no external library, nothing fetched from a CDN).
 * Each entry is "emoji keywords..." so the search box can find it by name.
 */
const CATEGORIES: { id: string; icon: string; title: string; items: string[] }[] = [
  {
    id: 'smileys',
    icon: '😀',
    title: 'Smileys',
    items: [
      '😀 grin happy smile', '😃 smile happy', '😄 laugh smile', '😁 beam grin', '😆 laugh squint', '😅 sweat laugh',
      '🤣 rofl rolling laugh', '😂 joy tears laugh lol', '🙂 slight smile', '🙃 upside down', '😉 wink', '😊 blush smile',
      '😇 angel halo', '🥰 love hearts', '😍 heart eyes love', '🤩 star struck', '😘 kiss', '😗 kiss', '😚 kiss closed',
      '😋 yum tongue', '😛 tongue', '😜 wink tongue', '🤪 zany crazy', '😝 squint tongue', '🤑 money mouth rich',
      '🤗 hug', '🤭 oops hand mouth', '🤫 shush quiet', '🤔 thinking hmm', '🤐 zipper', '🤨 raised eyebrow',
      '😐 neutral', '😑 expressionless', '😶 no mouth', '😏 smirk', '😒 unamused', '🙄 eye roll', '😬 grimace',
      '😮‍💨 exhale relief', '🤥 lie', '😌 relieved', '😔 pensive', '😪 sleepy', '🤤 drool', '😴 sleep zzz',
      '😷 mask sick', '🤒 thermometer sick', '🤕 hurt bandage', '🤢 nausea', '🤮 vomit', '🥵 hot', '🥶 cold',
      '🥴 woozy', '😵 dizzy', '🤯 mind blown', '🤠 cowboy', '🥳 party celebrate', '😎 cool sunglasses', '🤓 nerd',
      '🧐 monocle', '😕 confused', '😟 worried', '🙁 frown', '😮 surprised wow', '😯 hushed', '😲 astonished',
      '😳 flushed', '🥺 pleading puppy', '😦 frown open', '😧 anguish', '😨 fear', '😰 anxious sweat', '😥 sad relieved',
      '😢 cry tear', '😭 sob crying', '😱 scream', '😖 confounded', '😣 persevere', '😞 disappointed', '😓 sweat',
      '😩 weary', '😫 tired', '🥱 yawn', '😤 triumph huff', '😡 angry rage', '😠 angry', '🤬 cursing',
      '😈 devil smile', '💀 skull dead', '💩 poop', '🤡 clown', '👻 ghost', '👽 alien', '🤖 robot',
    ],
  },
  {
    id: 'people',
    icon: '👍',
    title: 'Gestures & people',
    items: [
      '👍 thumbs up yes like ok', '👎 thumbs down no', '👌 ok perfect', '🤌 pinched italian', '✌️ peace victory',
      '🤞 fingers crossed luck', '🤟 love you', '🤘 rock', '🤙 call me', '👈 left', '👉 right', '👆 up', '👇 down',
      '☝️ point up', '✋ hand stop', '🤚 raised back', '🖐️ hand fingers', '🖖 vulcan', '👋 wave hello bye',
      '👏 clap applause', '🙌 raise hands praise', '👐 open hands', '🤲 palms up', '🤝 handshake deal', '🙏 pray thanks please',
      '✍️ writing', '💅 nails', '💪 muscle strong', '🦾 mechanical arm', '🧠 brain smart', '👀 eyes look', '👁️ eye',
      '👅 tongue', '👄 lips', '💋 kiss lips', '👶 baby', '🧒 child', '👦 boy', '👧 girl', '🧑 person', '👨 man',
      '👩 woman', '🧓 older', '👴 old man', '👵 old woman', '🙋 raising hand', '🙇 bow', '🤦 facepalm', '🤷 shrug',
      '💁 info', '🙆 ok gesture', '🙅 no gesture', '🧑‍💻 developer coder', '🧑‍💼 office worker', '🧑‍🚀 astronaut',
      '🕺 dance man', '💃 dance woman', '🏃 run', '🚶 walk', '🧘 yoga meditate', '👑 crown king', '🎩 top hat',
    ],
  },
  {
    id: 'hearts',
    icon: '❤️',
    title: 'Hearts & symbols',
    items: [
      '❤️ heart love red', '🧡 orange heart', '💛 yellow heart', '💚 green heart', '💙 blue heart', '💜 purple heart',
      '🖤 black heart', '🤍 white heart', '🤎 brown heart', '💔 broken heart', '❤️‍🔥 heart fire', '❣️ heart exclamation',
      '💕 two hearts', '💞 revolving hearts', '💓 beating heart', '💗 growing heart', '💖 sparkling heart', '💘 cupid',
      '💝 heart ribbon gift', '💯 hundred 100', '💢 anger', '💥 boom collision', '💫 dizzy star', '💦 sweat drops',
      '💨 dash', '💬 speech', '💭 thought', '💤 zzz sleep', '✅ check done yes', '☑️ checkbox', '✔️ check',
      '❌ cross no', '❎ cross mark', '➕ plus', '➖ minus', '❓ question', '❗ exclamation', '‼️ double exclamation',
      '⚠️ warning', '🚫 prohibited', '⭕ circle', '🔴 red circle', '🟢 green circle', '🔵 blue circle', '⭐ star',
      '🌟 glowing star', '✨ sparkles', '⚡ zap lightning', '🔥 fire lit hot', '🎉 tada party', '🎊 confetti',
      '♻️ recycle', '🔒 lock', '🔓 unlock', '🔑 key', '🛡️ shield', '⚖️ scale balance', '♾️ infinity', '🆗 ok button',
      '🆕 new', '🆒 cool', '🔝 top', '🔜 soon', '💲 dollar', '💱 exchange',
    ],
  },
  {
    id: 'nature',
    icon: '🐶',
    title: 'Animals & nature',
    items: [
      '🐶 dog puppy', '🐱 cat kitten', '🐭 mouse', '🐹 hamster', '🐰 rabbit bunny', '🦊 fox', '🐻 bear', '🐼 panda',
      '🐨 koala', '🐯 tiger', '🦁 lion', '🐮 cow', '🐷 pig', '🐸 frog', '🐵 monkey', '🙈 see no evil', '🙉 hear no evil',
      '🙊 speak no evil', '🐔 chicken', '🐧 penguin', '🐦 bird', '🦅 eagle', '🦉 owl', '🦄 unicorn', '🐝 bee',
      '🦋 butterfly', '🐢 turtle', '🐍 snake', '🐙 octopus', '🐬 dolphin', '🐳 whale', '🦈 shark', '🐘 elephant',
      '🐎 horse', '🐂 ox bull', '🐻‍❄️ polar bear', '🌵 cactus', '🌲 tree', '🌴 palm', '🍀 clover luck', '🌸 blossom',
      '🌹 rose', '🌻 sunflower', '🌷 tulip', '🍁 maple leaf', '🌍 earth globe', '🌙 moon', '☀️ sun', '⛅ cloud sun',
      '🌧️ rain', '⛈️ storm', '❄️ snow', '🌈 rainbow', '🌊 wave ocean',
    ],
  },
  {
    id: 'food',
    icon: '🍕',
    title: 'Food & drink',
    items: [
      '🍏 green apple', '🍎 apple', '🍊 orange', '🍋 lemon', '🍌 banana', '🍉 watermelon', '🍇 grapes', '🍓 strawberry',
      '🫐 blueberries', '🍒 cherries', '🍑 peach', '🥭 mango', '🍍 pineapple', '🥥 coconut', '🥑 avocado', '🍅 tomato',
      '🌶️ chili hot', '🌽 corn', '🥕 carrot', '🥔 potato', '🍞 bread', '🧀 cheese', '🥚 egg', '🍳 cooking', '🥞 pancakes',
      '🥓 bacon', '🍗 chicken leg', '🍔 burger', '🍟 fries', '🍕 pizza', '🌭 hot dog', '🥪 sandwich', '🌮 taco',
      '🌯 burrito', '🍝 pasta', '🍜 ramen noodles', '🍛 curry', '🍣 sushi', '🍱 bento', '🥟 dumpling', '🍦 ice cream',
      '🍩 donut', '🍪 cookie', '🎂 birthday cake', '🍰 cake', '🧁 cupcake', '🍫 chocolate', '🍿 popcorn', '☕ coffee',
      '🍵 tea', '🧃 juice', '🥤 soda', '🍺 beer', '🍻 cheers beers', '🥂 champagne cheers', '🍷 wine', '🥃 whisky',
      '🍸 cocktail', '🍾 bottle celebrate',
    ],
  },
  {
    id: 'activity',
    icon: '⚽',
    title: 'Activities & travel',
    items: [
      '⚽ soccer football', '🏀 basketball', '🏈 american football', '⚾ baseball', '🎾 tennis', '🏐 volleyball',
      '🏏 cricket', '🏓 ping pong', '🏸 badminton', '⛳ golf', '🥊 boxing', '🏆 trophy win', '🥇 gold medal first',
      '🥈 silver medal', '🥉 bronze medal', '🎯 target bullseye', '🎮 game controller', '🎲 dice', '♟️ chess',
      '🎨 art palette', '🎬 movie clapper', '🎤 microphone', '🎧 headphones', '🎵 music note', '🎸 guitar', '🎹 piano',
      '🚗 car', '🏎️ race car', '🚕 taxi', '🚌 bus', '🚆 train', '✈️ plane flight', '🚀 rocket launch moon', '🛳️ ship',
      '⛵ sailboat', '🏖️ beach', '🏝️ island', '🏔️ mountain', '🗽 statue liberty', '🗼 tower', '🏰 castle', '🏠 house home',
      '🏢 office building', '🏦 bank', '🌆 city', '🗺️ map', '🧳 luggage travel',
    ],
  },
  {
    id: 'objects',
    icon: '💡',
    title: 'Objects',
    items: [
      '📱 phone mobile', '💻 laptop computer', '🖥️ desktop', '⌨️ keyboard', '🖱️ mouse', '💾 floppy save', '📷 camera',
      '📹 video camera', '📺 tv', '⏰ alarm clock', '⌛ hourglass', '⏳ hourglass flowing', '💡 idea bulb', '🔦 flashlight',
      '🕯️ candle', '💸 money flying', '💵 dollar banknote', '💶 euro', '💷 pound', '💴 yen', '💰 money bag', '🪙 coin',
      '💳 credit card', '💎 gem diamond', '📈 chart up stonks', '📉 chart down', '📊 bar chart', '🧾 receipt', '✉️ envelope',
      '📧 email', '📦 package box', '📝 memo note', '📁 folder', '📄 document page', '📌 pin', '📎 paperclip', '✂️ scissors',
      '🔧 wrench', '🔨 hammer', '⚙️ gear', '🧲 magnet', '🔬 microscope', '🔭 telescope', '💊 pill', '🩺 stethoscope',
      '🛒 cart', '🎁 gift present', '🎈 balloon', '🪄 magic wand', '📚 books', '🔔 bell', '📣 megaphone', '🗝️ old key',
      '⛓️ chain blockchain', '🪪 id card', '🏷️ label tag', '📅 calendar date',
    ],
  },
  {
    id: 'flags',
    icon: '🏁',
    title: 'Flags',
    items: [
      '🏁 checkered flag finish', '🚩 red flag', '🏳️ white flag', '🏴 black flag', '🏳️‍🌈 rainbow flag', '🇮🇳 india',
      '🇺🇬 uganda', '🇰🇪 kenya', '🇹🇿 tanzania', '🇷🇼 rwanda', '🇿🇦 south africa', '🇳🇬 nigeria', '🇦🇪 uae emirates',
      '🇸🇦 saudi', '🇬🇧 uk britain', '🇺🇸 usa america', '🇨🇦 canada', '🇨🇳 china', '🇯🇵 japan', '🇰🇷 korea', '🇸🇬 singapore',
      '🇦🇺 australia', '🇩🇪 germany', '🇫🇷 france', '🇮🇹 italy', '🇪🇸 spain', '🇨🇭 switzerland', '🇳🇱 netherlands',
      '🇧🇷 brazil', '🇲🇽 mexico', '🇪🇺 european union',
    ],
  },
];

const RECENT_KEY = 'zyphra_recent_emoji';
const MAX_RECENT = 24;

function parse(entry: string): { e: string; k: string } {
  const i = entry.indexOf(' ');
  return i < 0 ? { e: entry, k: '' } : { e: entry.slice(0, i), k: entry.slice(i + 1) };
}

function readRecent(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string').slice(0, MAX_RECENT) : [];
  } catch {
    return [];
  }
}

function pushRecent(e: string): string[] {
  const next = [e, ...readRecent().filter((x) => x !== e)].slice(0, MAX_RECENT);
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    // storage unavailable (private mode): recents just are not kept
  }
  return next;
}

export const EmojiPicker: React.FC<{
  open: boolean;
  onClose: () => void;
  onPick: (emoji: string) => void;
  /** Elements that should NOT close the picker when clicked (e.g. the button that toggles it). */
  ignoreRef?: React.RefObject<HTMLElement | null>;
}> = ({ open, onClose, onPick, ignoreRef }) => {
  const [query, setQuery] = useState('');
  const [recent, setRecent] = useState<string[]>(() => (typeof window === 'undefined' ? [] : readRecent()));
  const [activeCat, setActiveCat] = useState<string>('smileys');
  const popRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const parsed = useMemo(() => CATEGORIES.map((c) => ({ ...c, list: c.items.map(parse) })), []);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setRecent(readRecent());
    const t = setTimeout(() => searchRef.current?.focus(), 30);
    const onDown = (e: MouseEvent | TouchEvent) => {
      const target = e.target as Node;
      if (popRef.current?.contains(target)) return;
      if (ignoreRef?.current?.contains(target)) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('touchstart', onDown, { passive: true });
    document.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(t);
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('touchstart', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, onClose, ignoreRef]);

  if (!open) return null;

  const q = query.trim().toLowerCase();
  const results = q
    ? parsed.flatMap((c) => c.list).filter((x) => x.k.includes(q) || x.e === q)
    : [];

  const pick = (e: string) => {
    setRecent(pushRecent(e));
    onPick(e);
  };

  const jumpTo = (id: string) => {
    setActiveCat(id);
    setQuery('');
    requestAnimationFrame(() => {
      const el = bodyRef.current?.querySelector<HTMLElement>(`[data-cat="${id}"]`);
      if (el && bodyRef.current) bodyRef.current.scrollTo({ top: el.offsetTop - 4 });
    });
  };

  const grid = (items: { e: string; k: string }[]) => (
    <div className="ig-emoji-grid">
      {items.map((x) => (
        <button key={x.e} type="button" title={x.k.split(' ')[0] || x.e} aria-label={x.k.split(' ')[0] || x.e} onClick={() => pick(x.e)}>
          {x.e}
        </button>
      ))}
    </div>
  );

  return (
    <div className="ig-emoji-pop" ref={popRef} role="dialog" aria-label="Choose an emoji">
      <input
        ref={searchRef}
        className="ig-emoji-search"
        type="search"
        placeholder="Search emoji"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        aria-label="Search emoji"
      />
      {!q && (
        <div className="ig-emoji-tabs" role="tablist" aria-label="Emoji categories">
          {recent.length > 0 && (
            <button type="button" role="tab" aria-selected={activeCat === 'recent'} title="Recent" onClick={() => jumpTo('recent')}>
              🕘
            </button>
          )}
          {parsed.map((c) => (
            <button key={c.id} type="button" role="tab" aria-selected={activeCat === c.id} title={c.title} onClick={() => jumpTo(c.id)}>
              {c.icon}
            </button>
          ))}
        </div>
      )}
      <div
        className="ig-emoji-body"
        ref={bodyRef}
        onScroll={(e) => {
          if (q) return;
          const body = e.currentTarget;
          const sections = Array.from(body.querySelectorAll<HTMLElement>('[data-cat]'));
          const current = sections.filter((s) => s.offsetTop - body.scrollTop <= 24).pop();
          if (current?.dataset.cat && current.dataset.cat !== activeCat) setActiveCat(current.dataset.cat);
        }}
      >
        {q ? (
          results.length ? grid(results) : <div className="ig-emoji-empty">No emoji found for “{query}”.</div>
        ) : (
          <>
            {recent.length > 0 && (
              <div data-cat="recent">
                <div className="ig-emoji-section-title">Recent</div>
                {grid(recent.map((e) => ({ e, k: '' })))}
              </div>
            )}
            {parsed.map((c) => (
              <div key={c.id} data-cat={c.id}>
                <div className="ig-emoji-section-title">{c.title}</div>
                {grid(c.list)}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
};

/** Inserts text at the caret of a textarea/input and returns the new value + caret position. */
export function insertAtCaret(
  el: HTMLTextAreaElement | HTMLInputElement | null,
  current: string,
  text: string
): { value: string; caret: number } {
  if (!el) return { value: current + text, caret: (current + text).length };
  const start = el.selectionStart ?? current.length;
  const end = el.selectionEnd ?? current.length;
  const value = current.slice(0, start) + text + current.slice(end);
  return { value, caret: start + text.length };
}
