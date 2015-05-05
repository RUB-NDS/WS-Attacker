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
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public final class CryptoConstants
{

    /**
     * AES works for a block size of 128 bits (16 bytes)
     */
    public static final int AES_BLOCK_SIZE = 16;

    /**
     * DES / 3DES works for a block size of 64 bits (8 bytes)
     */
    public static final int DES_BLOCK_SIZE = 8;

    /**
     * Algorithm enum with some constants
     */
    public enum Algorithm
    {

        CBC_3DES( 8, 24, "3DES/CBC/NoPadding", "3DES" ), CBC_AES128( 16, 16, "AES/CBC/NoPadding", "AES" ), CBC_AES192(
            16, 24, "AES/CBC/NoPadding", "AES" ), CBC_AES256( 16, 32, "AES/CBC/NoPadding", "AES" );
        public int BLOCK_SIZE;

        public int KEY_SIZE;

        public String JAVA_NAME;

        public String KEY_SPEC_NAME;

        private Algorithm( int blockSize, int keyLength, String javaName, String keySpecName )
        {
            this.BLOCK_SIZE = blockSize;
            this.KEY_SIZE = keyLength;
            this.JAVA_NAME = javaName;
            this.KEY_SPEC_NAME = keySpecName;
        }
    }

    private CryptoConstants()
    {
    }

    /**
     * Returns an algorithm with all its properties according to an XML Encryption constant defined in
     * <url>http://www.w3.org/TR/xmlenc-core/#sec-AlgID</url>
     * 
     * @param xmlencConstant XML Encryption algorithm
     * @return
     */
    public static Algorithm getAlgorithm( String xmlencConstant )
    {
        switch ( xmlencConstant )
        {
            case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                return Algorithm.CBC_AES128;
            case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
                return Algorithm.CBC_AES192;
            case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                return Algorithm.CBC_AES256;
            case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
                return Algorithm.CBC_3DES;
            default:
                return null;
        }
    }
}
