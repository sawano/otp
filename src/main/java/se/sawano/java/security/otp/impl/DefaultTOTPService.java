/*
 * Copyright 2017 Daniel Sawano
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.sawano.java.security.otp.impl;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.StringUtils;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.TOTPService;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.stream.LongStream;

import static org.apache.commons.lang3.Validate.notNull;
import static se.sawano.java.security.otp.TOTP.totp;
import static se.sawano.java.security.otp.impl.WindowSize.windowSize;

// TODO keep track of used TOTP codes (only successful) (as per RFC)
public class DefaultTOTPService implements TOTPService {

    /**
     * Default Unix time to start counting time steps (0).
     */
    public static final Instant T0_UTC = Instant.EPOCH;

    /**
     * Default time step (30s)
     */
    public static final Duration STEP_SIZE = Duration.ofSeconds(30);

    /**
     * Default window size (3).
     */
    public static final WindowSize DEFAULT_WINDOW_SIZE = windowSize(3);

    private static final Map<ShaAlgorithm, BiFunction<SharedSecret, byte[], byte[]>> HMAC_SUPPLIERS = new HashMap<>();

    static {
        HMAC_SUPPLIERS.put(ShaAlgorithm.SHA1, (secret, steps) -> HmacUtils.hmacSha1(secret.value(), steps));
        HMAC_SUPPLIERS.put(ShaAlgorithm.SHA256, (secret, steps) -> HmacUtils.hmacSha256(secret.value(), steps));
        HMAC_SUPPLIERS.put(ShaAlgorithm.SHA512, (secret, steps) -> HmacUtils.hmacSha512(secret.value(), steps));
    }

    private static final Map<TOTP.Length, Integer> DIGITS_POWER_OF_10 = new HashMap<>();

    static {
        Arrays.stream(TOTP.Length.values())
              .forEach(length -> DIGITS_POWER_OF_10.put(length, (int) Math.pow(10, length.value())));
    }

    private final Clock clock;
    private final Instant t0;
    private final Duration stepSize;
    private final WindowSize windowSize;

    /**
     * Creates a {@link TOTPService}. The created service will use default TOTP values, which are: UTC time, Unix epoch
     * (0) as {@code T0}, and a time step of 30 seconds.
     */
    public DefaultTOTPService() {
        this(() -> java.time.Clock.systemUTC().instant(), T0_UTC, STEP_SIZE, DEFAULT_WINDOW_SIZE);
    }

    /**
     * Creates a new {@link DefaultTOTPService} with the provided parameters.
     *
     * @param clock
     *         The {@link Clock} to use for getting the current time. Default is UTC time.
     * @param t0
     *         The Unix time to start counting time steps. Default is Unix epoch (0).
     * @param stepSize
     *         The size of the time step to use. Default is 30 seconds.
     *
     * @see #T0_UTC
     * @see #STEP_SIZE
     */
    public DefaultTOTPService(final Clock clock, final Instant t0, final Duration stepSize, final WindowSize windowSize) {
        notNull(clock);
        notNull(t0);
        notNull(stepSize);
        notNull(windowSize);

        this.clock = clock;
        this.t0 = t0;
        this.stepSize = stepSize;
        this.windowSize = windowSize;
    }

    @Override
    public TOTP create(final SharedSecret secret, final TOTP.Length length) {
        notNull(secret);
        notNull(length);

        return create(secret, length, numberOfSteps());
    }

    private long numberOfSteps() {
        final long now = clock.now().toEpochMilli();
        return (now - t0.toEpochMilli()) / stepSize.toMillis();
    }

    private TOTP create(final SharedSecret secret, final TOTP.Length length, final long numberOfSteps) {
        final byte[] numberOfStepsBytes = toHexBytes(numberOfSteps);

        final byte[] hashBytes = getHmacFunction(secret.algorithm()).apply(secret, numberOfStepsBytes);

        final int binary = truncate(hashBytes);

        final int totp = binary % DIGITS_POWER_OF_10.get(length);

        return totp(totp, length);
    }

    @Override
    public boolean verify(final TOTP totp, final SharedSecret secret) {
        notNull(totp);
        notNull(secret);

        final long numberOfSteps = numberOfSteps();

        final boolean isOk = LongStream.rangeClosed(-windowSize.value() / 2, windowSize.value() / 2)
                                       .map(i -> numberOfSteps + i)
                                       .mapToObj(steps -> verify(totp, secret, steps))
                                       .anyMatch(Boolean.TRUE::equals);

        // TODO resynchronization may take place here
        // TODO register valid totp code as "consumed" so it can't be used again
        return isOk;
    }

    private boolean verify(final TOTP totp, final SharedSecret secret, final long steps) {

        final TOTP expectedTotp = create(secret, totp.length(), steps);
        return expectedTotp.equals(totp);
    }

    private static BiFunction<SharedSecret, byte[], byte[]> getHmacFunction(final ShaAlgorithm shaAlgorithm) {
        return Optional.ofNullable(HMAC_SUPPLIERS.get(shaAlgorithm))
                       .orElseThrow(() -> new IllegalArgumentException("Unsupported algorithm: " + shaAlgorithm));
    }

    private static byte[] toHexBytes(final long value) {
        try {
            final String hexValue = StringUtils.leftPad(Long.toHexString(value), 16, '0');
            return Hex.decodeHex(hexValue.toCharArray());
        } catch (final DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Truncates the hash. I.e. converts it to binary code, which is a 31-bit, unsigned,
     * big-endian integer; the first byte is masked with a 0x7f. (see RFC4226)
     */
    private static int truncate(final byte[] hash) {
        final int offset = hash[hash.length - 1] & 0xf;

        return ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);
    }
}
