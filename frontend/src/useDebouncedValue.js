import { useEffect, useState } from 'react';

/**
 * The value, updated only after it has stopped changing for `delay` ms.
 * Search boxes stay responsive while the expensive list filtering waits
 * until the user pauses typing.
 */
export default function useDebouncedValue(value, delay = 200) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}
