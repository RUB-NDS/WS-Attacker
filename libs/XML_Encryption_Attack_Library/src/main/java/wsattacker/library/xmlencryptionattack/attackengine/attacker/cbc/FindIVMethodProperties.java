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
package wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class FindIVMethodProperties
{

    public enum Type
    {
        IBM_DATAPOWER, DEFAULT, UNDEFINED
    };

    private boolean blockDecrypted;

    private final byte[] decryptedBytes;

    private final boolean[] byteDecrypted;

    private Type type;

    public FindIVMethodProperties( final int blockLength )
    {
        decryptedBytes = new byte[blockLength];
        byteDecrypted = new boolean[blockLength];
        type = Type.UNDEFINED;
    }

    public void setByte( int i, byte b )
    {
        decryptedBytes[i] = b;
        byteDecrypted[i] = true;
        for ( int j = 0; j < byteDecrypted.length; j++ )
        {
            if ( byteDecrypted[j] == false )
            {
                return;
            }
        }
        blockDecrypted = true;
    }

    public byte getByte( int i )
    {
        return decryptedBytes[i];
    }

    public boolean isBlockDecrypted()
    {
        return blockDecrypted;
    }

    public boolean isByteDecrypted( int i )
    {
        return byteDecrypted[i];
    }

    public byte[] getDecryptedBytes()
    {
        return decryptedBytes;
    }

    public Type getType()
    {
        return type;
    }

    public void setType( Type type )
    {
        this.type = type;
    }

}
