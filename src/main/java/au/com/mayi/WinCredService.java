
package au.gov.aec.genesis.credential;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import au.gov.aec.genesis.credential.data.Credential;
import au.gov.aec.genesis.credential.data.CredentialType;
import au.gov.aec.genesis.credential.data.GenericCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

public class WinCredService
{
    private static final Logger LOG = LoggerFactory.getLogger(WinCredService.class);

    public List<GenericCredential> genericCredentials;

    public WinCredService()
    {
        genericCredentials = new ArrayList<>();
        enumerateGenericCredentials();
        LOG.info("Windows Credential Manager Service initialised.");
    }

    public GenericCredential getByTargetName(String targetName)
    {

        for (GenericCredential gwc : genericCredentials)
        {
            if (gwc.getAddress().equals(targetName))
            {
                return gwc;
            }
        }
        return null;
    }

    private void enumerateGenericCredentials()
    {
        IntByReference pCount = new IntByReference();
        PointerByReference pCredentials = new PointerByReference();

        boolean result = Advapi32Credentials.INSTANCE.CredEnumerateW(null,
                                                                     0,
                                                                     pCount,
                                                                     pCredentials);
        if (Boolean.TRUE.equals(result))
        {
            Pointer[] ps = pCredentials.getValue().getPointerArray(0,
                                                                   pCount.getValue());

            for (int i = 0; i < pCount.getValue(); i++)
            {

                Credential arrRef = new Credential(ps[i]);
                arrRef.read();
                if (CredentialType.valueOf(arrRef.Type) == CredentialType.CRED_TYPE_GENERIC)
                { // only generic credentials

                    GenericCredential gwc = new GenericCredential();
                    gwc.setAddress(arrRef.TargetName.getWideString(0)); // address
                    gwc.setUsername(getUserName(arrRef)); // username

                    if (arrRef.CredentialBlobSize > 0)
                    {
                        byte[] bytes = arrRef.CredentialBlob.getByteArray(0,
                                                                          arrRef.CredentialBlobSize);

                        gwc.setPassword(new String(bytes,
                                                   StandardCharsets.UTF_16LE)); // password
                    }

                    genericCredentials.add(gwc);

                }
            }
        }
    }

    private String getUserName(Credential arrRef)
    {
        if (arrRef.UserName != null)
        {
            return arrRef.UserName.getWideString(0);
        }

        return null;
    }

}
