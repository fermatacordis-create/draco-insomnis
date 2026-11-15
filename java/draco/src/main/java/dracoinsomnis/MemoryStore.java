package dracoinsomnis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.function.DoubleSupplier;

/** One process; thread-safe; lost on restart. */
public final class MemoryStore implements Store {
    private record Item(String value, double until) {}

    private final Map<String, Item> items = new HashMap<>();
    private final DoubleSupplier now;

    public MemoryStore() {
        this(Clock::now);
    }

    /** @param now the time in seconds (for tests). */
    public MemoryStore(DoubleSupplier now) {
        this.now = now;
    }

    private Item live(String key) {
        Item it = items.get(key);
        if (it == null) return null;
        if (it.until != 0 && it.until <= now.getAsDouble()) {
            items.remove(key);
            return null;
        }
        return it;
    }

    private void sweep() {
        if (items.size() < 50_000) return;
        for (String k : new ArrayList<>(items.keySet())) live(k);
    }

    @Override
    public synchronized long bump(String key, int ttl) {
        Item it = live(key);
        long n = 1;
        if (it != null) {
            try {
                n = Long.parseLong(it.value) + 1;
            } catch (NumberFormatException e) {
                n = 1;
            }
        }
        items.put(key, new Item(Long.toString(n), it == null ? now.getAsDouble() + ttl : it.until));
        sweep();
        return n;
    }

    @Override
    public synchronized String get(String key) {
        Item it = live(key);
        return it == null ? null : it.value;
    }

    @Override
    public synchronized void set(String key, String value, int ttl) {
        items.put(key, new Item(value, ttl == 0 ? 0 : now.getAsDouble() + ttl));
        sweep();
    }

    @Override
    public synchronized void delete(String key) {
        items.remove(key);
    }
}
