package org.plovdev.keyer.utils;

import org.plovdev.keyer.Platform;

/**
 * Utility class for system environment detection.
 * <p>
 * Provides methods to identify the current operating system to ensure
 * the correct native {@link org.plovdev.keyer.Keychain} implementation is loaded.
 *
 * @author Anton
 * @version 1.0
 */
public final class PlatformUtils {
    /**
     * Private constructor to prevent instantiation of this utility class.
     *
     * @throws UnsupportedOperationException always.
     */
    private PlatformUtils() {
        throw new UnsupportedOperationException();
    }

    /**
     * Detects the current operating system based on the {@code "os.name"} system property.
     * <p>
     * Supported platforms include:
     * <ul>
     *     <li>{@link Platform#MAC} - for macOS systems</li>
     *     <li>{@link Platform#WINDOWS} - for Windows systems</li>
     *     <li>{@link Platform#UNIX} - for Linux and other Unix-systems</li>
     * </ul>
     *
     * @return the detected {@link Platform} enum value.
     */
    public static Platform guessPlatform() {
        String osName = System.getProperty("os.name").trim().toLowerCase();
        if (osName.contains("mac")) {
            return Platform.MAC;
        } else if (osName.contains("win")) {
            return Platform.WINDOWS;
        } else if (osName.contains("nix") || osName.contains("nux") || osName.contains("aix")) {
            return Platform.UNIX;
        }
        return Platform.OTHER;
    }
}