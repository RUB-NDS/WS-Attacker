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

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class CBCOracleRequest
    extends OracleRequest
{

    /**
     * CBCOracleRequest consisting of an initialization vector and of one ciphertext block
     * 
     * @param iv
     * @param c1
     */
    public CBCOracleRequest( byte[] iv, byte[] c1 )
    {
        this.encryptedData = new byte[iv.length * 2];
        System.arraycopy( iv, 0, encryptedData, 0, iv.length );
        System.arraycopy( c1, 0, encryptedData, iv.length, c1.length );
    }
}
