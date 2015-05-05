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

package wsattacker.library.xmlencryptionattack.util;

/**
 * List of constants for the different engines.
 * 
 * @author Dennis Kupset
 */
public final class XMLEncryptionConstants
{

    /**
     * Namespace of XML Encryption
     */
    final public static String URI_NS_ENC = "http://www.w3.org/2001/04/xmlenc#";

    final public static String ENC_TYPE_ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element";

    final public static String ENC_TYPE_CONTENT = "http://www.w3.org/2001/04/xmlenc#Content";

    final public static int NO_CURR_WRAP_IDX = -1;

    final public static int DEFAULT_IDX = 0;

    public enum OracleMode
    {
        ERROR_ORACLE
    }; // TIMING_ORACLE?

    public enum WrappingAttackMode
    {
        NO_WRAP, SIGNATURE, ENCRYPTION, SIG_ENC_WRAP
    };

    public enum CryptoTechnique
    {
        SYMMETRIC, ASYMMETRIC, HYBRID
    };

    public enum XMLEncryptionAttackMode
    {
        CBC_ATTACK( CryptoTechnique.SYMMETRIC ), PKCS1_ATTACK( CryptoTechnique.ASYMMETRIC );
        CryptoTechnique m_CryptoTechnique;

        private XMLEncryptionAttackMode( CryptoTechnique cryptotechnique )
        {
            this.m_CryptoTechnique = cryptotechnique;
        }

        public CryptoTechnique getCryptoTechnique()
        {
            return m_CryptoTechnique;
        }
    }

    private XMLEncryptionConstants()
    {

    }

}
