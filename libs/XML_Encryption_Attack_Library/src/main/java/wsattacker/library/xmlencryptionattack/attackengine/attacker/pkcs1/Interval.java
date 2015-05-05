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
package wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1;

import java.math.BigInteger;

/**
 * M interval as mentioned in the Bleichenbacher paper.
 * 
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 May 24, 2012
 */
public class Interval
{

    public BigInteger lower;

    public BigInteger upper;

    public Interval( BigInteger a, BigInteger b )
    {
        this.lower = a;
        this.upper = b;
        if ( a.compareTo( b ) > 0 )
        {
            throw new RuntimeException( "something went wrong, a cannot be greater than b" );
        }
    }
}
