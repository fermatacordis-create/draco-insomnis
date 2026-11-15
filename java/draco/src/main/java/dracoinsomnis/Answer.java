package dracoinsomnis;

/**
 * What stops a request: 403 (a rule), 429 (the pace) or 200 (the review thanks page).
 *
 * @param status the HTTP status
 * @param why the rule, for the evidence only (the page never shows it)
 * @param retry seconds for Retry-After (429)
 * @param form the review form of the 403 page, or ""
 */
public record Answer(int status, String why, int retry, String form) {
    public Answer(int status, String why) {
        this(status, why, 0, "");
    }

    Answer withForm(String f) {
        return new Answer(status, why, retry, f);
    }
}
