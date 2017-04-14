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

package se.sawano.java.security.otp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.TOTPService;
import se.sawano.java.security.otp.impl.WindowSize;
import se.sawano.java.security.otp.rfc6238.ReferenceDataRepository;
import se.sawano.java.security.otp.rfc6238.ReferenceDataRepository.ReferenceData;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class TOTPServiceRegressionTests {

    // Seed for HMAC-SHA1 - 20 bytes
    private static final String seed = "3132333435363738393031323334353637383930";
    // Seed for HMAC-SHA256 - 32 bytes
    private static final String seed32 = "3132333435363738393031323334353637383930" +
            "313233343536373839303132";
    // Seed for HMAC-SHA512 - 64 bytes
    private static final String seed64 = "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "31323334";
    private static final Instant T0 = Instant.EPOCH;
    private static final Duration STEP_SIZE = Duration.ofSeconds(30);
    private static final WindowSize WINDOW_SIZE = WindowSize.windowSize(3);

    private static final Map<ReferenceData.Mode, ShaAlgorithm> modeToAlgorithmMap = new HashMap<>();

    static {
        modeToAlgorithmMap.put(ReferenceData.Mode.SHA1, ShaAlgorithm.SHA1);
        modeToAlgorithmMap.put(ReferenceData.Mode.SHA256, ShaAlgorithm.SHA256);
        modeToAlgorithmMap.put(ReferenceData.Mode.SHA512, ShaAlgorithm.SHA512);
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        return new ReferenceDataRepository().init().data().stream()
                                            .map(data -> new Object[]{data})
                                            .collect(toList());
    }

    @Parameterized.Parameter(0)
    public ReferenceData data;

    @Test
    public void should_create_same_totp_as_reference_implementation() throws Exception {
        final TOTP totp = new TOTPService(() -> data.time, T0, STEP_SIZE, WINDOW_SIZE).create(secretFor(data),
                                                                                              TOTP.Length.EIGHT
        );

        assertEquals(data.totp, totp.value());
    }

    private ShaAlgorithm algorithm(final ReferenceData.Mode mode) {
        return modeToAlgorithmMap.get(mode);
    }

    private SharedSecret secretFor(final ReferenceData data) {
        if (ReferenceData.Mode.SHA1.equals(data.mode)) {
            return SharedSecret.fromHex(seed, algorithm(data.mode));
        }
        if (ReferenceData.Mode.SHA256.equals(data.mode)) {
            return SharedSecret.fromHex(seed32, algorithm(data.mode));
        }
        if (ReferenceData.Mode.SHA512.equals(data.mode)) {
            return SharedSecret.fromHex(seed64, algorithm(data.mode));
        }
        throw new IllegalArgumentException("Unsupported mode: " + data.mode);
    }

}