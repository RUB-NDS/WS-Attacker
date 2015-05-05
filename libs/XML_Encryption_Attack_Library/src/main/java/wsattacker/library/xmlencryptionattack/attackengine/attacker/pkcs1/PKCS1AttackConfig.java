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

import java.security.interfaces.RSAPublicKey;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.PKCS1StrategyFactory;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.PKCS1StrategyFactory.PKCS1Strategy;

/**
 * @author Dennis
 */
public final class PKCS1AttackConfig
{
    private RSAPublicKey m_ServerRSAPubKey = null;

    private PKCS1StrategyFactory.PKCS1Strategy m_PKCS1Strategy = PKCS1Strategy.CBC_WEAK;

    public PKCS1AttackConfig()
    {

    }

    public PKCS1StrategyFactory.PKCS1Strategy getPKCS1Strategy()
    {
        return m_PKCS1Strategy;
    }

    public void setPKCS1Strategy( PKCS1StrategyFactory.PKCS1Strategy pKCS1Strategy )
    {
        this.m_PKCS1Strategy = pKCS1Strategy;
    }

    public RSAPublicKey getServerRSAPubKey()
    {
        return m_ServerRSAPubKey;
    }

    public void setServerRSAPubKey( RSAPublicKey serverRSAPubKey )
    {
        this.m_ServerRSAPubKey = serverRSAPubKey;
    }

}
