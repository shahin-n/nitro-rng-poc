package com.mario.rng.reveal;

import net.fellbaum.jemoji.Emoji;
import net.fellbaum.jemoji.EmojiGroup;
import net.fellbaum.jemoji.EmojiManager;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

/**
 * Builds the noise-padded "hash_result" payload and its commit hash — ported verbatim
 * from the production {@code com.taixiu.unbalanced.core.security.ResultProcessor}.
 *
 * <p>The dice/number generation is NOT done here: the caller (the enclave RNG) rolls the
 * result and passes it as {@code resultText} (e.g. {@code "1-1-4"}). This class only wraps
 * that result in random noise + emojis so the small result space cannot be brute-forced
 * from the committed hash before reveal.
 *
 * <p>Payload shape:
 * <pre>#{randAlpha}{sessionId}_{noise[0..i]}{{resultText}}{noise[i..]}{emoji × noiseEmojiLength}</pre>
 * commit = {@code encrypt(payload)} (SHA256/MD5 hex), or the raw payload when useEncryption is false.
 */
public abstract class ResultProcessor {

    protected static final char[] allCharsArr = ("1234567890"
            + "qwertyuiopasdfghjklzxcvbnm"
            + "@#$%"
            + "QWERTYUIOPASDFGHJKLZXCVBNM").toCharArray();

    private static final char[] LETTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

    protected final Random random = new SecureRandom();

    protected final int noiseStringLength;
    protected final int noiseEmojiLength;
    protected final boolean useEncryption;
    protected final double noiseAdjustmentCoefficient;
    protected final Emoji[] allEmoji;

    protected ResultProcessor(NoiseConfig cfg) {
        int len = cfg.noiseStringLength();
        if (len == 0) {
            len = NoiseConfig.DEFAULT_NOISE_STRING_LENGTH;
        }
        this.noiseStringLength = len;
        this.noiseEmojiLength = cfg.noiseEmojiLength();
        this.useEncryption = cfg.useEncryption();
        this.noiseAdjustmentCoefficient = cfg.noiseAdjustmentCoefficient();
        this.allEmoji = EMOJI_POOL;
    }

    /** The jemoji pool is constant; scan it once. */
    private static final Emoji[] EMOJI_POOL = initEmoji();

    /** The committed payload plus its hash. The client re-hashes {@code payload} to verify {@code commit}. */
    public record NoiseResult(String payload, String commit, String encryptionType) {
    }

    /**
     * Build the noise-wrapped payload for {@code resultText} (e.g. "1-1-4") and hash it.
     * {@code sessionId} is embedded verbatim (may be empty).
     */
    public NoiseResult handle(String sessionId, String resultText) {
        String session = sessionId == null ? "" : sessionId;

        // shorten the noise by up to (length * coefficient), matching production
        int span = (int) (noiseStringLength * noiseAdjustmentCoefficient);
        int cut = span > 0 ? random.nextInt(span) : 0;
        int noiseLen = noiseStringLength - cut;

        String noise = randomFrom(noiseLen, allCharsArr);
        String wrapped = "{" + resultText + "}";
        int splitAt = random.nextInt(noise.length() + 1);
        String randomBeforeSession = randomFrom(random.nextInt(10), LETTERS);

        StringBuilder sb = new StringBuilder();
        sb.append("#").append(randomBeforeSession).append(session).append("_")
                .append(noise, 0, splitAt)
                .append(wrapped)
                .append(noise.substring(splitAt));
        for (int i = 0; i < noiseEmojiLength; i++) {
            sb.append(allEmoji[random.nextInt(allEmoji.length)].getEmoji());
        }

        String payload = sb.toString();
        String commit = useEncryption ? encrypt(payload) : payload;
        return new NoiseResult(payload, commit, getEncryptionType());
    }

    protected abstract String encrypt(String input);

    public abstract String getEncryptionType();

    private String randomFrom(int count, char[] pool) {
        StringBuilder b = new StringBuilder(Math.max(count, 0));
        for (int i = 0; i < count; i++) {
            b.append(pool[random.nextInt(pool.length)]);
        }
        return b.toString();
    }

    /** Same emoji pool as production: TRAVEL_AND_PLACES + SMILEYS_AND_EMOTION + FOOD_AND_DRINK minus a removelist. */
    private static Emoji[] initEmoji() {
        List<Emoji> emojis = new LinkedList<>();
        emojis.addAll(EmojiManager.getAllEmojisByGroup(EmojiGroup.TRAVEL_AND_PLACES));
        emojis.addAll(EmojiManager.getAllEmojisByGroup(EmojiGroup.SMILEYS_AND_EMOTION));
        emojis.addAll(EmojiManager.getAllEmojisByGroup(EmojiGroup.FOOD_AND_DRINK));

        // exact surrogate escapes from the production source (avoids copy/paste glyph drift)
        String removeEmoji = "🫡,🫢,🛝,🛞,"
                + "🫨,🫤,🩷,🫢,🛟,"
                + "🩵,🫥,🩶,🫠,🥹,"
                + "🫣,🫗,🫙,🫚,🫘,🫛";

        Set<Emoji> removeSet = new HashSet<>();
        for (String chars : removeEmoji.split(",")) {
            Optional<Emoji> e = EmojiManager.getEmoji(chars);
            e.ifPresent(removeSet::add);
        }
        emojis.removeAll(removeSet);
        return emojis.toArray(new Emoji[0]);
    }
}
