/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.library.intelligentdos.dos;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;

import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX31A;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX33A;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionInterface;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class HashCollisionTest
{

    private final HashCollision hashCollision = new HashCollision();

    @Test
    public void hasFurther()
    {
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneIteration()
    {
        hashCollision.setCollisionGenerators( new CollisionInterface[] { new CollisionDJBX31A() } );
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();
        assertThat( hashCollision.hasFurtherParams(), is( false ) );
    }

    @Test
    public void twoTwoTwo()
    {
        // two collision interfaces
        hashCollision.setCollisionGenerators( new CollisionInterface[] { new CollisionDJBX31A(), new CollisionDJBX33A() } );
        // two number of attributes
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        // use namespace: true and false
        hashCollision.setUseNamespace( new Boolean[] { Boolean.FALSE, Boolean.TRUE } );

        for ( int i = 0; i < 8; i++ )
        {
            assertThat( hashCollision.hasFurtherParams(), is( true ) );
            hashCollision.nextParam();
        }

        assertThat( hashCollision.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        hashCollision.getTamperedRequest( "", PayloadPosition.ELEMENT );
    }

    @Test( expected = IllegalArgumentException.class )
    public void nullPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        hashCollision.getTamperedRequest( "", null );
    }

    @Test
    public void tampered()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ATTRIBUTE;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        hashCollision.setCollisionGenerators( new CollisionInterface[] { new CollisionDJBX31A() } );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();

        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        String tampered = " tt=\"0\" uU=\"1\" />";
        assertThat( hashCollision.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        tampered = " tttt=\"0\" ttuU=\"1\" ttv6=\"2\" uUtt=\"3\" />";
        assertThat( hashCollision.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( hashCollision.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untampered()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ATTRIBUTE;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        hashCollision.setCollisionGenerators( new CollisionInterface[] { new CollisionDJBX31A() } );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 12 ).setIncrement( 8 ).build();

        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        String tamperedRequest = hashCollision.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = hashCollision.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertTrue( untamperedRequest.matches( ".*? [a-zA-Z]{3}0=\"0\" [a-zA-Z]{3}1=\"1\" [a-zA-Z]{3}2=\"2\" [a-zA-Z]{3}3=\"3\" />.*" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        tamperedRequest = hashCollision.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = hashCollision.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertTrue( untamperedRequest.matches( ".*? ([a-zA-Z]{4}[0-9]{2}=\"[0-9]\" ){10}([a-zA-Z]{4}[0-9]{2}=\"[0-9]{2}\" ){2}/>.*" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( hashCollision.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untamperedWithNamespace()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ATTRIBUTE;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        hashCollision.setCollisionGenerators( new CollisionInterface[] { new CollisionDJBX31A() } );
        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 4 ).build();
        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        hashCollision.setUseNamespace( new Boolean[] { Boolean.TRUE } );
        assertThat( hashCollision.hasFurtherParams(), is( true ) );
        hashCollision.nextParam();

        String tamperedRequest = hashCollision.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = hashCollision.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertTrue( untamperedRequest.matches( ".*? xmlns:[a-zA-Z]{3}0=\"0\" xmlns:[a-zA-Z]{3}1=\"1\" xmlns:[a-zA-Z]{3}2=\"2\" xmlns:[a-zA-Z]{3}3=\"3\" />.*" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( hashCollision.hasFurtherParams(), is( false ) );
    }

    @Test
    public void cloneTest()
        throws CloneNotSupportedException
    {
        // two collision interfaces
        hashCollision.setCollisionGenerators( new CollisionInterface[] { new CollisionDJBX31A(), new CollisionDJBX33A() } );
        // two number of attributes
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        hashCollision.setNumberOfCollisionsIterator( iterateModel );
        // use namespace: true and false
        hashCollision.setUseNamespace( new Boolean[] { Boolean.FALSE, Boolean.TRUE } );

        List<DoSAttack> attacks = new ArrayList<DoSAttack>();
        for ( int i = 0; i < 8; i++ )
        {
            assertThat( hashCollision.hasFurtherParams(), is( true ) );
            hashCollision.nextParam();
            attacks.add( hashCollision.clone() );
        }

        assertThat( hashCollision.hasFurtherParams(), is( false ) );

        String[] collision = { "CollisionDJBX31A", "CollisionDJBX33A" };
        String[] namespace = { "false", "true" };
        String[] number = { "2", "4" };

        for ( int i = 0; i < 8; i++ )
        {
            int c = i / 4;
            int na = ( i / 2 ) % 2;
            int n = i % 2;
            DoSAttack doSAttack = attacks.get( i );
            List<DoSParam<?>> currentParams = doSAttack.getCurrentParams();

            assertThat( currentParams.get( 0 ).getValueAsString(), is( collision[c] ) );
            assertThat( currentParams.get( 1 ).getValueAsString(), is( namespace[na] ) );
            assertThat( currentParams.get( 2 ).getValueAsString(), is( number[n] ) );
        }
    }

}
