package org.plovdev.keyer.implementations.mac;

import org.jetbrains.annotations.Nullable;
import org.plovdev.keyer.utils.NativeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;

import static org.plovdev.keyer.utils.NativeUtils.find;

/**
 * Low-level native bridge for macOS Keychain access using Project Panama.
 * <p>
 * This class interacts directly with {@code Security.framework} to perform
 * CRUD operations on Generic Password items. It handles:
 * <ul>
 *     <li>Native memory allocation and deallocation via {@link Arena}</li>
 *     <li>Downcalls to C functions using {@link MethodHandle}</li>
 *     <li>Automatic reinterpretation of native memory segments</li>
 * </ul>
 *
 * <p><b>Safety Note:</b> This class is intended for internal use by {@link MacKeychain}.
 * Direct usage requires careful management of {@code OSStatus} codes and memory lifecycle.</p>
 *
 * @author Anton
 * @version 1.0
 */
public final class MacOsKeychainNative {
    private static final Logger log = LoggerFactory.getLogger(MacOsKeychainNative.class);

    private static final String ADD_PASSWORD_METHOD_NAME = "SecKeychainAddGenericPassword";
    private static final String GET_PASSWORD_METHOD_NAME = "SecKeychainFindGenericPassword";
    private static final String DELETE_PASSWORD_METHOD_NAME = "SecKeychainItemDelete";
    private static final String CLEAN_PASSWORD_METHOD_NAME = "SecKeychainItemFreeContent";

    private static final Arena SHARED = Arena.ofAuto();
    private static final Linker LINKER = Linker.nativeLinker();

    /**
     * Path to the binary inside the Security framework.
     */
    private static final SymbolLookup SECURITY = SymbolLookup.libraryLookup("/System/Library/Frameworks/Security.framework/Versions/A/Security", SHARED);

    private static final MethodHandle ADD_PASSWORD = find(SECURITY, LINKER, ADD_PASSWORD_METHOD_NAME, FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle GET_PASSWORD = find(SECURITY, LINKER, GET_PASSWORD_METHOD_NAME, FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle DELETE_PASSWORD = find(SECURITY, LINKER, DELETE_PASSWORD_METHOD_NAME, FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    private static final MethodHandle CLEAN_PASSWORD = find(SECURITY, LINKER, CLEAN_PASSWORD_METHOD_NAME, FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    /**
     * Fetches a password from the Keychain.
     *
     * @param app   the service name (appId)
     * @param alias the account name
     * @return password as char array, or null if not found
     * @throws RuntimeException if a native call fails unexpectedly
     */
    public char @Nullable [] getPassword(String app, String alias) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment appSegment = arena.allocateFrom(app);
            MemorySegment aliasSegment = arena.allocateFrom(alias);
            MemorySegment lenPtr = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment dataPtr = arena.allocate(ValueLayout.ADDRESS);

            int status = (int) GET_PASSWORD.invokeExact(MemorySegment.NULL, (int) appSegment.byteSize() - 1, appSegment, (int) aliasSegment.byteSize() - 1, aliasSegment, lenPtr, dataPtr, MemorySegment.NULL);
            log.trace("Password getting status: {}", status);
            if (status != 0) return null;

            MemorySegment passwordData = dataPtr.get(ValueLayout.ADDRESS, 0).reinterpret(lenPtr.get(ValueLayout.JAVA_INT, 0));
            byte[] bytes = passwordData.toArray(ValueLayout.JAVA_BYTE);
            char[] password = NativeUtils.bytesToCharsUTF_8(bytes);

            int cleanStatus = (int) CLEAN_PASSWORD.invokeExact(MemorySegment.NULL, passwordData);
            Arrays.fill(bytes, (byte) 0);
            return password;
        } catch (Throwable t) {
            throw new RuntimeException("Error to get password: ");
        }
    }

    /**
     * Saves a password. Attempts to delete any existing entry first to prevent duplicates.
     *
     * @param app         the service name
     * @param alias       the account name
     * @param newPassword password to save
     * @throws RuntimeException if the save operation fails
     */
    public void setPassword(String app, String alias, char[] newPassword) {
        try {
            deletePassword(app, alias);
        } catch (Throwable t) {
            log.debug("Error to clean password defore setting: ", t);
        }
        try (var arena = Arena.ofConfined()) {
            var s = arena.allocateFrom(app);
            var a = arena.allocateFrom(alias);
            byte[] passBytes = NativeUtils.charsUTF_8ToBytes(newPassword);
            var p = arena.allocateFrom(ValueLayout.JAVA_BYTE, passBytes);

            int status = (int) ADD_PASSWORD.invokeExact(MemorySegment.NULL, (int) s.byteSize() - 1, s, (int) a.byteSize() - 1, a, (int) p.byteSize(), p, MemorySegment.NULL);
            Arrays.fill(passBytes, (byte) 0);
        } catch (Throwable t) {
            throw new RuntimeException("Cann't set password");
        }
    }

    /**
     * Deletes a specific keychain item.
     *
     * @param app   the service name
     * @param alias the account name
     * @throws RuntimeException if the item exists but cannot be deleted
     */
    public void deletePassword(String app, String alias) {
        try (var arena = Arena.ofConfined()) {
            var s = arena.allocateFrom(app);
            var a = arena.allocateFrom(alias);
            var itemRef = arena.allocate(ValueLayout.ADDRESS);

            int status = (int) GET_PASSWORD.invokeExact(MemorySegment.NULL, (int) s.byteSize() - 1, s, (int) a.byteSize() - 1, a, MemorySegment.NULL, MemorySegment.NULL, itemRef);
            if (status == 0) {
                int delStatus = (int) DELETE_PASSWORD.invokeExact(itemRef.get(ValueLayout.ADDRESS, 0));
            } else {
                throw new RuntimeException("Unable to delete password, status: " + status);
            }
        } catch (Throwable t) {
            throw new RuntimeException("Error to delete password");
        }
    }
}