/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request;

import org.opensaml.xml.util.Base64;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class OracleRequest
{

    /**
     * EncryptedKey (PKCS1) part that is going to be sent to the server. If set to null, the original request is not
     * modified.
     */
    byte[] encryptedKey;

    /**
     * EncryptedData (CBC) part that is going to be sent to the server. If set to null, the original request is not
     * modified.
     */
    byte[] encryptedData;

    public byte[] getEncryptedKey()
    {
        return encryptedKey;
    }

    public void setEncryptedKey( byte[] encryptedKey )
    {
        this.encryptedKey = encryptedKey;
    }

    public byte[] getEncryptedData()
    {
        return encryptedData;
    }

    public void setEncryptedData( byte[] encryptedData )
    {
        this.encryptedData = encryptedData;
    }

    public String getEncryptedKeyBase64()
    {
        return Base64.encodeBytes( encryptedKey );
    }

    public void setEncryptedKeyBase64( String encryptedKeyBase64 )
    {
        this.encryptedKey = Base64.decode( encryptedKeyBase64 );
    }

    public String getEncryptedDataBase64()
    {
        return Base64.encodeBytes( encryptedData );
    }

    public void setEncryptedDataBase64( String encryptedDataBase64 )
    {
        this.encryptedData = Base64.decode( encryptedDataBase64 );
    }
}
