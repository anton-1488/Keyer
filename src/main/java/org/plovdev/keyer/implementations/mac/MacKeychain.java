package org.plovdev.keyer.implementations.mac;

import org.plovdev.keyer.Keychain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final Logger log = LoggerFactory.getLogger(MacKeychain.class);

    /**
     * Native bridge for Project Panama calls.
     */
    private static final MacOsKeychainNative MAC_OS_KEYCHAIN_NATIVE = new MacOsKeychainNative();

    // state variables
    private final AtomicBoolean isInited = new AtomicBoolean(false);
    private String appId;

    /**
     * {@inheritDoc}
     * <p>Sets the {@code appId} as the 'Service' attribute for macOS keychain items.</p>
     */
    @Override
    public synchronized void init(String appId) {
        if (isInited.get()) return;
        this.appId = appId;
        isInited.set(true);
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException if called before {@link #init(String)}.
     */
    @Override
    public synchronized char[] getPassword(String alias) {
        checkIfInited();
        return MAC_OS_KEYCHAIN_NATIVE.getPassword(appId, alias);
    }

    /**
     * {@inheritDoc}
     * <p>Overwrites the password if the alias already exists for this application.</p>
     *
     * @throws IllegalStateException if called before {@link #init(String)}.
     */
    @Override
    public synchronized boolean setPassword(String alias, char[] newPassword) {
        checkIfInited();
        try {
            MAC_OS_KEYCHAIN_NATIVE.setPassword(appId, alias, newPassword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException if called before {@link #init(String)}.
     */
    @Override
    public synchronized boolean deletePassword(String alias) {
        checkIfInited();
        try {
            MAC_OS_KEYCHAIN_NATIVE.deletePassword(appId, alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Ensures that the keychain instance has been properly initialized with an appId.
     *
     * @throws IllegalStateException if {@code isInited} is false.
     */
    private void checkIfInited() {
        if (!isInited.get()) {
            throw new IllegalStateException("Keyer not inited!");
        }
    }
}