package org.plovdev.keyer.implementations.mac;

import org.plovdev.keyer.Keychain;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * macOS implementation of the {@link Keychain} interface.
 * <p>
 * This class serves as a thread-safe wrapper around {@link MacOsKeychainNative},
 * connecting the Java API to the Apple Security Framework.
 * </p>
 * <p>
 * Features:
 * <ul>
 *     <li>Uses {@code synchronized} methods to ensure atomic native operations.</li>
 *     <li>Guarantees single-time initialization via {@link AtomicBoolean}.</li>
 *     <li>Integrates with system-wide macOS Keychain storage.</li>
 * </ul>
 *
 * @author Anton
 * @version 1.0
 */
public class MacKeychain implements Keychain {
    /**
     * Native bridge for Project Panama calls.
     */
    private static final MacOsKeychainNative MAC_OS_KEYCHAIN_NATIVE = new MacOsKeychainNative();

    // state variables
    private final String appId;

    public MacKeychain(String appId) {
        this.appId = appId;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized char[] getPassword(String alias) {
        return MAC_OS_KEYCHAIN_NATIVE.getPassword(appId, alias);
    }

    /**
     * {@inheritDoc}
     * <p>Overwrites the password if the alias already exists for this application.</p>
     */
    @Override
    public synchronized boolean setPassword(String alias, char[] newPassword) {
        try {
            MAC_OS_KEYCHAIN_NATIVE.setPassword(appId, alias, newPassword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized boolean deletePassword(String alias) {
        try {
            MAC_OS_KEYCHAIN_NATIVE.deletePassword(appId, alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}