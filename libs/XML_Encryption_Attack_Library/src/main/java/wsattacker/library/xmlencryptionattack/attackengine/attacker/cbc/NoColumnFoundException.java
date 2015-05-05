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
 * This exception can occur by decrypting a concrete byte by the FindByteMethod. If it occurs, it means that the
 * function was not able to identify the ASCII column the original byte was defined. The reason could e.g. be that the
 * plaintext contains some special characters (This attack implementation does handle only ASCII characters).
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class NoColumnFoundException
    extends Exception
{

    private String message;

    public NoColumnFoundException( int i )
    {
        message = "No column was found for byte " + i + ". Probably, this byte " + "is excluded by the padding";
    }

    public NoColumnFoundException( String s )
    {
        this.message = s;
    }

    @Override
    public String getMessage()
    {
        return message;
    }
}
