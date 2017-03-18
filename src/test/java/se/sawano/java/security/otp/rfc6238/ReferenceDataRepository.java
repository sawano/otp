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

package se.sawano.java.security.otp.rfc6238;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.Validate.validState;
import static se.sawano.java.commons.lang.Streams.toOnlyOne;

public class ReferenceDataRepository {

    public static final String SHARED_SECRET = "12345678901234567890";
    public static final Duration TIME_STEP = Duration.ofSeconds(30);
    public static final Instant T0 = Instant.EPOCH;
    private static final Logger LOGGER = LoggerFactory.getLogger(ReferenceDataRepository.class);

    private List<ReferenceData> referenceData;

    public ReferenceDataRepository() {
    }

    public ReferenceDataRepository init() {
        referenceData = readData();
        LOGGER.info("Read {} test data(s) from file", referenceData.size());
        return this;
    }

    private static List<ReferenceData> readData() {
        return readLines().filter(l -> !l.startsWith("#"))
                          .map(ReferenceDataRepository::createData)
                          .collect(toList());
    }

    private static Stream<String> readLines() {
        try {
            @SuppressWarnings("ConstantConditions")
            final String file = ReferenceDataRepository.class.getClassLoader().getResource("reference-data-rfc6238.txt").getFile();
            final Path p = new File(file).toPath();
            return Files.lines(p);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static ReferenceData createData(final String line) {
        final StringTokenizer tokenizer = new StringTokenizer(line, "|");
        tokenizer.nextToken(); // Remove first blank token

        return new ReferenceData.Builder()
                .withTime(Instant.ofEpochSecond(Long.valueOf(next(tokenizer))))
                .withUtcTime(next(tokenizer))
                .withHexTime(next(tokenizer))
                .withTotp(next(tokenizer))
                .withMode(ReferenceData.Mode.fromCode(next(tokenizer)))
                .createTestData();

    }

    public List<ReferenceData> data() {
        validState(referenceData != null, "Test data not initialized");
        return referenceData;
    }

    public ReferenceData getForMode(final ReferenceData.Mode mode) {
        return get(p -> p.mode.equals(mode))
                .orElseThrow(() -> new RuntimeException("No test data found for mode: " + mode));
    }

    private Optional<ReferenceData> get(final Predicate<ReferenceData> predicate) {
        return data().stream()
                     .filter(predicate)
                     .findFirst();
    }

    private static String next(final StringTokenizer tokenizer) {
        return tokenizer.nextToken().trim();
    }

    public static class ReferenceData {
        public enum Mode {
            SHA1("SHA1"),
            SHA256("SHA256"),
            SHA512("SHA512");

            private final String mode;

            Mode(final String mode) {
                this.mode = mode;
            }

            public static Mode fromCode(final String code) {
                return Arrays.stream(values())
                             .filter(m -> m.mode.equals(code))
                             .reduce(toOnlyOne(code))
                             .orElseThrow(() -> new IllegalArgumentException("No mode found for code: '" + code + "'"));
            }

        }

        public final Instant time;
        public final String utcTime;
        public final String hexTime;
        public final String totp;
        public final Mode mode;

        ReferenceData(final Instant time, final String utcTime, final String hexTime, final String totp, final Mode mode) {
            this.time = time;
            this.utcTime = utcTime;
            this.hexTime = hexTime;
            this.totp = totp;
            this.mode = mode;
        }

        @Override
        public String toString() {
            return "ReferenceData{" +
                    "time=" + time +
                    ", utcTime='" + utcTime + '\'' +
                    ", hexTime='" + hexTime + '\'' +
                    ", totp='" + totp + '\'' +
                    ", mode=" + mode +
                    '}';
        }

        private static class Builder {
            private Instant time;
            private String utcTime;
            private String hexTime;
            private String totp;
            private Mode mode;

            public Builder withTime(final Instant time) {
                this.time = time;
                return this;
            }

            public Builder withUtcTime(final String utcTime) {
                this.utcTime = utcTime;
                return this;
            }

            public Builder withHexTime(final String hexTime) {
                this.hexTime = hexTime;
                return this;
            }

            public Builder withTotp(final String totp) {
                this.totp = totp;
                return this;
            }

            public Builder withMode(final Mode mode) {
                this.mode = mode;
                return this;
            }

            public ReferenceData createTestData() {
                return new ReferenceData(time, utcTime, hexTime, totp, mode);
            }
        }

    }

}
