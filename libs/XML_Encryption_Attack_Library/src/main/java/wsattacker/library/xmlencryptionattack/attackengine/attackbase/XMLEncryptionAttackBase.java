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

package wsattacker.library.xmlencryptionattack.attackengine.attackbase;

import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants.Algorithm;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.CryptoTechnique;

/**
 * @author dennis
 * @version 1.0
 * @created 18-Feb-2014 10:50:04
 */
public abstract class XMLEncryptionAttackBase
{
    protected CryptoTechnique m_CryptoTechnique;

    protected Algorithm m_AttackedAlgoritm;

    public Algorithm getAttackedAlgoritm()
    {
        return m_AttackedAlgoritm;
    }

    public void setAttackedAlgoritm( Algorithm attackedAlgoritm )
    {
        this.m_AttackedAlgoritm = attackedAlgoritm;
    }

    public CryptoTechnique getCryptoTechnique()
    {
        return m_CryptoTechnique;
    }

    public void setCryptoTechnique( CryptoTechnique cryptoTechnique )
    {
        this.m_CryptoTechnique = cryptoTechnique;
    }

    public abstract byte[] executeAttack()
        throws CryptoAttackException;
}