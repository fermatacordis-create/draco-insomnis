package dracoinsomnis;

final class Clock {
    private Clock() {}

    /** Unix time in seconds, with milliseconds. */
    static double now() {
        return System.currentTimeMillis() / 1000.0;
    }
}
