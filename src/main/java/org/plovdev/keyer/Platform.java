package org.plovdev.keyer;

/**
 * Supported operating system platforms for native keychain access.
 * <p>
 * This enum is used by {@link org.plovdev.keyer.utils.PlatformUtils}
 * and {@link org.plovdev.keyer.Keychain} to determine the appropriate
 * native implementation for secure storage.
 *
 * @author Anton
 * @version 1.0
 */
public enum Platform {
    /**
     * Microsoft Windows operating systems.
     * Uses Windows Credential Manager as the backend.
     */
    WINDOWS,

    /**
     * Apple macOS operating systems.
     * Uses macOS Keychain as the backend.
     */
    MAC,

    /**
     * Linux and Unix-systems.
     * Typically, uses Libsecret as the backend.
     */
    UNIX,

    /**
     * Any other operating system that is not officially supported by Keyer.
     */
    OTHER
}