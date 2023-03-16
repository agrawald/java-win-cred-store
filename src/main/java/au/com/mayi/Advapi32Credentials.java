package au.gov.aec.genesis.credential;

import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

public interface Advapi32Credentials
        extends StdCallLibrary {
    Advapi32Credentials INSTANCE = (Advapi32Credentials) Native.loadLibrary("advapi32", Advapi32Credentials.class);

    /*
    BOOL CredEnumerate(
        _In_  LPCTSTR     Filter,
        _In_  DWORD       Flags,
        _Out_ DWORD       *Count,
        _Out_ PCREDENTIAL **Credentials) */
    boolean CredEnumerateW(String filter, int flags, IntByReference count, PointerByReference pref);
}
