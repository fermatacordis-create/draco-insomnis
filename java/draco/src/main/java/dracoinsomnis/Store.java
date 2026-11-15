package dracoinsomnis;

/**
 * Counters, the block list and verified crawlers. The keys are the same as in the JavaScript, Python,
 * Go, Ruby and .NET editions, so one Redis can serve apps in several languages.
 */
public interface Store {
    /** Adds one and returns the new value; the counter disappears after ttl seconds. */
    long bump(String key, int ttl);

    /** The value, or null when there is none (or it expired). */
    String get(String key);

    /** Keeps a value for ttl seconds; 0 = for good. */
    void set(String key, String value, int ttl);

    void delete(String key);
}
