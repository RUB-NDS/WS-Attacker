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
package wsattacker.library.intelligentdos;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.apache.commons.math3.stat.descriptive.SynchronizedDescriptiveStatistics;
import org.apache.log4j.Logger;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestType;
import static wsattacker.library.intelligentdos.common.RequestType.TAMPERED;
import static wsattacker.library.intelligentdos.common.RequestType.UNTAMPERED;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.CoerciveParsing;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.dos.HashCollision;
import wsattacker.library.intelligentdos.dos.XmlAttributeCount;
import wsattacker.library.intelligentdos.dos.XmlElementCount;
import wsattacker.library.intelligentdos.dos.XmlEntityExpansion;
import wsattacker.library.intelligentdos.dos.XmlExternalEntity;
import wsattacker.library.intelligentdos.dos.XmlOverlongNames;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.position.Position;
import wsattacker.library.intelligentdos.position.PositionIterator;
import wsattacker.library.intelligentdos.success.SuccessDecider;

/**
 * @author Christian Altmeier
 */
public class IntelligentDoSLibraryImpl
    implements IntelligentDoSLibrary
{

    private static final int UTR_THREADS = 4;

    private static final int UTR_REQUESTS = 8;

    public static final int DEFAULT_SERVER_RECOVERY = 20000;

    public static final List<CommonParamItem> COMMONPARAMS = new ArrayList<CommonParamItem>();

    private static final int[][] DEFAULTCOMMONPARAMS = { { 16, 2, 750 }, { 16, 2, 500 }, { 24, 4, 500 },
        { 24, 4, 250 }, { 32, 8, 250 }, { 128, 8, 250 } };

    static
    {
        for ( int[] commonParam : DEFAULTCOMMONPARAMS )
        {
            COMMONPARAMS.add( new CommonParamItem( commonParam ) );
        }
    }

    private final static Logger LOG = Logger.getLogger( IntelligentDoSLibraryImpl.class );

    private final String xmlMessage;

    private final PositionIterator positionIterator;

    private boolean hasFurtherAttack;

    boolean noFurtherIterations = false;

    private int serverRecovery = 0;

    private List<CommonParamItem> commonParamList;

    // array with all possible attacks
    private DoSAttack[] attacks = getAllAttacks();

    // attacks
    private Iterator<DoSAttack> attackIterator;

    // attack specific payload positions
    private Iterator<PayloadPosition> payloadPositionIterator;

    // common attack parameter
    private Iterator<CommonParamItem> commonParamsIterator;

    private AttackModel currentAttack;

    // current parameters
    private DoSAttack currentDoSAttack;

    private PayloadPosition currentPayloadPosition;

    private Position currentPosition;

    private CommonParamItem currentCommonParams;

    private SuccessDecider successDecider;

    private Long[] currentUntampered;

    private final List<SuccessfulAttack> successfulAttackList;

    private final List<DoSAttack> notPossibleList;

    private final List<Threshold> thresholdList;

    private double maximumRequestsPerSecond;

    // Init state
    private DoSState doSState = new InitialState();

    private boolean m_needRecovery;

    // statistic about the last request
    private final DescriptiveStatistics testProbeStatisticsShort = new SynchronizedDescriptiveStatistics( 10 );

    private final DescriptiveStatistics testProbeStatisticsLong = new SynchronizedDescriptiveStatistics( 100 );

    private final SummaryStatistics untamperedStatistics = new SummaryStatistics();

    public IntelligentDoSLibraryImpl( String xmlMessage, PositionIterator positionIterator )
    {
        if ( xmlMessage == null )
        {
            throw new IllegalArgumentException( "xmlMessage cannot be null!" );
        }
        if ( positionIterator == null )
        {
            throw new IllegalArgumentException( "positionIterator cannot be null!" );
        }

        this.positionIterator = positionIterator;
        this.xmlMessage = xmlMessage;

        successfulAttackList = new ArrayList<SuccessfulAttack>();
        notPossibleList = new ArrayList<DoSAttack>();
        thresholdList = new ArrayList<Threshold>();

        commonParamList = COMMONPARAMS;
    }

    @Override
    public void initialize()
    {
        attackIterator = Arrays.asList( attacks ).iterator();

        for ( DoSAttack doSAttack : attacks )
        {
            doSAttack.initialize();
        }

        currentDoSAttack = attackIterator.next();
        LOG.info( "start with " + currentDoSAttack.getName() );

        payloadPositionIterator = Arrays.asList( currentDoSAttack.getPossiblePossitions() ).iterator();

        while ( payloadPositionIterator.hasNext() && !hasFurtherAttack )
        {
            currentPayloadPosition = payloadPositionIterator.next();

            if ( positionIterator.hasNext( currentPayloadPosition ) )
            {
                // only if we have some expansion points in the document, we can start
                // an attack
                hasFurtherAttack = true;
                currentPosition = positionIterator.next( currentPayloadPosition );
                currentAttack = createFirstAttack();
                doSState = new UntamperedState();
            }
        }

    }

    public static DoSAttack[] getAllAttacks()
    {
        return new DoSAttack[] { new CoerciveParsing(), new XmlElementCount(), new XmlAttributeCount(),
            new XmlEntityExpansion(), new XmlExternalEntity(), new HashCollision(), new XmlOverlongNames() };
    }

    @Override
    public void setAttacks( DoSAttack[] attacks )
    {
        this.attacks = new DoSAttack[attacks.length];
        System.arraycopy( attacks, 0, this.attacks, 0, attacks.length );
    }

    public void setSuccessDecider( SuccessDecider successDecider )
    {
        this.successDecider = successDecider;
    }

    public void setCommonParams( List<CommonParamItem> commonParamList )
    {
        this.commonParamList = commonParamList;
    }

    public void setServerRecoveryTime( int timeInMillies )
    {
        this.serverRecovery = timeInMillies;
    }

    void setDoSState( DoSState doSState )
    {
        String format = String.format( "switch state from %s to %s", this.doSState.getName(), doSState.getName() );
        LOG.trace( format );
        this.doSState = doSState;
    }

    AttackModel getCurrentAttack()
    {
        return currentAttack;
    }

    void setCurrentAttack( AttackModel currentAttack )
    {
        this.currentAttack = currentAttack;
    }

    void setHasFurtherAttack( boolean hasFurtherAttack )
    {
        this.hasFurtherAttack = hasFurtherAttack;
    }

    SuccessDecider getSuccessDecider()
    {
        return successDecider;
    }

    @Override
    public boolean hasFurtherAttack()
    {
        return hasFurtherAttack;
    }

    @Override
    public synchronized AttackModel nextAttack()
    {
        // set hasFurtherAttack to false because we cannot create a new attack
        // as long as we didn't update the measures
        hasFurtherAttack = false;

        return currentAttack;
    }

    @Override
    public synchronized void update( AttackModel attackModel )
    {
        // update dependent on the state
        doSState.update( this, attackModel );
    }

    @Override
    public void updateTestProbes( Metric metric )
    {

        // update dependent on the state
        doSState.updateTestProbes( metric );
        synchronized ( doSState )
        {
            testProbeStatisticsShort.addValue( metric.getDuration() );
            testProbeStatisticsLong.addValue( metric.getDuration() );

            // long round_s = Math.round( testProbeStatisticsShort.getMean() / 100000.0 );
            // long round_l = Math.round( testProbeStatisticsLong.getMean() / 100000.0 );
            // double utr = Math.round( untamperedStatistics.getMean() / 100000.0 );
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.IntelligentDoSLibrary#getSuccessfulAttacks ()
     */
    @Override
    public List<SuccessfulAttack> getSuccessfulAttacks()
    {
        return new ArrayList<SuccessfulAttack>( successfulAttackList );
    }

    @Override
    public List<DoSAttack> getNotPossible()
    {
        return new ArrayList<DoSAttack>( notPossibleList );
    }

    @Override
    public List<Threshold> getThresholds()
    {
        return new ArrayList<Threshold>( thresholdList );
    }

    private AttackModel createFirstAttack()
    {
        // TODO this has to be bound to the attack
        if ( currentDoSAttack.hasFurtherParams() )
        {
            currentDoSAttack.nextParam();
        }

        // common params
        commonParamsIterator = createCommonParamsIterator();
        currentCommonParams = commonParamsIterator.next();

        return createNewUntampered( false );
    }

    AttackModel createNextAttack()
    {
        return createNextAttack( false );
    }

    AttackModel createNextAttack( boolean needRecovery )
    {

        do
        {
            iterate();
        }
        while ( !noFurtherIterations && isNotWise() );

        AttackModel attack = null;
        if ( !noFurtherIterations )
        {
            if ( currentUntampered == null )
            {
                attack = createNewUntampered( needRecovery || m_needRecovery );
                m_needRecovery = false;
            }
            else
            {
                attack = createNewTampered( needRecovery );
            }
        }

        return attack;
    }

    private boolean isNotWise()
    {
        boolean wise = false;

        if ( currentPosition == null )
        {
            return true;
        }

        for ( DoSAttack doSAttack : notPossibleList )
        {
            if ( currentDoSAttack.getName().equals( doSAttack.getName() ) )
            {
                return true;
            }
        }

        if ( maximumRequestsPerSecond > 0 && currentCommonParams.getReuqestsPerSecond() > maximumRequestsPerSecond )
        {
            return true;
        }

        for ( Threshold threshold : thresholdList )
        {
            // Same DoS Attack and params > 0
            if ( currentDoSAttack.getName().equals( threshold.getMinimum().getName() )
                && currentDoSAttack.compareTo( threshold.getMinimum() ) > 0 )
            {
                return true;
            }
        }

        for ( SuccessfulAttack successfulAttack : successfulAttackList )
        {
            if ( currentPosition.equals( successfulAttack.getPosition() )
                && currentPayloadPosition == successfulAttack.getPayloadPosition()
                && currentDoSAttack.equals( successfulAttack.getDoSAttack() ) )
            {
                return true;
            }
        }

        return wise;
    }

    private void iterate()
    {
        if ( commonParamsIterator.hasNext() )
        {
            currentCommonParams = commonParamsIterator.next();

        }
        else if ( positionIterator.hasNext( currentPayloadPosition ) )
        {
            // reset common attack parameter
            commonParamsIterator = createCommonParamsIterator();

            currentPosition = positionIterator.next( currentPayloadPosition );

            currentCommonParams = commonParamsIterator.next();

        }
        else if ( payloadPositionIterator.hasNext() )
        {
            // reset common attack parameter
            commonParamsIterator = createCommonParamsIterator();

            // extension points
            positionIterator.reset();

            currentPayloadPosition = payloadPositionIterator.next();

            currentPosition = positionIterator.next( currentPayloadPosition );

            currentCommonParams = commonParamsIterator.next();

        }
        else if ( currentDoSAttack.hasFurtherParams() )
        {
            // reset common attack parameter
            commonParamsIterator = createCommonParamsIterator();

            // extension points
            positionIterator.reset();

            // Possible PayloadPositions
            payloadPositionIterator = Arrays.asList( currentDoSAttack.getPossiblePossitions() ).iterator();

            // next attack parameter for the concrete dos attack
            currentDoSAttack.nextParam();

            position();

            currentCommonParams = commonParamsIterator.next();

            // reset utr
            currentUntampered = null;

        }
        else if ( attackIterator.hasNext() )
        {
            // reset common attack parameter
            commonParamsIterator = createCommonParamsIterator();

            // extension points
            positionIterator.reset();

            currentDoSAttack = attackIterator.next();
            LOG.info( "start with " + currentDoSAttack.getName() );

            // Possible PayloadPositions
            payloadPositionIterator = Arrays.asList( currentDoSAttack.getPossiblePossitions() ).iterator();

            // next attack parameter for the concrete dos attack
            currentDoSAttack.nextParam();

            position();

            currentCommonParams = commonParamsIterator.next();

            // reset utr
            currentUntampered = null;

            // request server recovery
            m_needRecovery = true;
        }
        else
        {
            // No further attacks
            noFurtherIterations = true;
        }
    }

    private void position()
    {
        currentPosition = null;
        while ( payloadPositionIterator.hasNext() && currentPosition == null )
        {
            currentPayloadPosition = payloadPositionIterator.next();

            if ( positionIterator.hasNext( currentPayloadPosition ) )
            {
                currentPosition = positionIterator.next( currentPayloadPosition );
            }
        }
    }

    AttackModel createNewTampered( boolean needRecovery )
    {
        AttackModel attackModel = createAttack( TAMPERED, currentCommonParams, needRecovery );

        String xmlWithPlaceholder = currentPosition.createPlaceholder( currentPayloadPosition );
        String content = currentDoSAttack.getTamperedRequest( xmlWithPlaceholder, currentPayloadPosition );
        attackModel.setRequestContent( content );

        attackModel.setPayloadPosition( currentPayloadPosition );
        attackModel.setPosition( currentPosition );

        return attackModel;
    }

    AttackModel createNewTampered( DoSAttack doSAttack )
    {
        AttackModel attackModel = createAttack( TAMPERED, currentCommonParams, false );
        attackModel.setDoSAttack( doSAttack );

        String xmlWithPlaceholder = currentPosition.createPlaceholder( currentPayloadPosition );
        String content = doSAttack.getTamperedRequest( xmlWithPlaceholder, currentPayloadPosition );
        attackModel.setRequestContent( content );

        attackModel.setPayloadPosition( currentPayloadPosition );
        attackModel.setPosition( currentPosition );

        return attackModel;
    }

    AttackModel createNewUntampered( DoSAttack doSAttack )
    {
        AttackModel attackModel = createAttack( UNTAMPERED, currentCommonParams, false );
        attackModel.setDoSAttack( doSAttack );

        String xmlWithPlaceholder = currentPosition.createPlaceholder( currentPayloadPosition );
        String content = doSAttack.getUntamperedRequest( xmlWithPlaceholder, currentPayloadPosition );
        attackModel.setRequestContent( content );

        attackModel.setPayloadPosition( currentPayloadPosition );
        attackModel.setPosition( currentPosition );

        return attackModel;
    }

    AttackModel createNewUntampered( boolean needRecovery )
    {
        CommonParamItem utr = new CommonParamItem( UTR_REQUESTS, UTR_THREADS, 750 );

        AttackModel attackModel = createNewUntampered( needRecovery, utr );

        return attackModel;
    }

    AttackModel createVerifyUntampered( boolean needRecovery )
    {
        AttackModel attackModel = createNewUntampered( needRecovery, currentCommonParams );

        return attackModel;
    }

    private AttackModel createNewUntampered( boolean needRecovery, CommonParamItem utr )
    {
        AttackModel attackModel = createAttack( UNTAMPERED, utr, needRecovery );

        String xmlWithPlaceholder = currentPosition.createPlaceholder( currentPayloadPosition );
        String content = currentDoSAttack.getUntamperedRequest( xmlWithPlaceholder, currentPayloadPosition );
        attackModel.setRequestContent( content );
        return attackModel;
    }

    private AttackModel createAttack( RequestType requestType, CommonParamItem commonParams, boolean needRecovery )
    {
        AttackModel attackModel = new AttackModel();
        attackModel.setRequestType( requestType );

        try
        {
            // Clone the dos attack, else we manipulate the "original" and cannot save the state
            attackModel.setDoSAttack( currentDoSAttack.clone() );
        }
        catch ( CloneNotSupportedException e )
        {
            LOG.info( e.getMessage(), e );
        }

        attackModel.setParamItem( commonParams );

        if ( needRecovery )
        {
            attackModel.setServerRecoveryBeforeSend( serverRecovery );
        }

        return attackModel;
    }

    @Override
    public boolean wasSuccessful()
    {
        return successfulAttackList.size() > 0;
    }

    @Override
    public String getTestProbeContent()
    {
        return xmlMessage;
    }

    private Iterator<CommonParamItem> createCommonParamsIterator()
    {
        return commonParamList.iterator();
    }

    public Long[] getCurrentUntampered()
    {
        Long[] copy = new Long[currentUntampered.length];
        System.arraycopy( currentUntampered, 0, copy, 0, currentUntampered.length );
        return copy;
    }

    void setCurrentUntampered( Long[] currentUntampered )
    {
        this.currentUntampered = currentUntampered;

        untamperedStatistics.clear();
        for ( Long value : currentUntampered )
        {
            untamperedStatistics.addValue( value );
        }
    }

    boolean addSuccessful( SuccessfulAttack successfulAttack )
    {
        LOG.info( "successful: " + successfulAttack );
        return successfulAttackList.add( successfulAttack );
    }

    void addNotPossible( DoSAttack doSAttack )
    {
        LOG.info( doSAttack.getName() + " is not possible against this Web Service" );
        notPossibleList.add( doSAttack );
    }

    @Override
    public double getMaximumRequestsPerSecond()
    {
        return maximumRequestsPerSecond;
    }

    void setMaximumRequestsPerSecond( double maximumRequestsPerSecond )
    {
        double fmrps = ( (int) ( maximumRequestsPerSecond * 100.0 ) ) / 100.0;
        LOG.info( "Threshold detected by " + fmrps + " requests per second." );
        this.maximumRequestsPerSecond = maximumRequestsPerSecond;
    }

    void addThreshold( Threshold threshold )
    {
        LOG.info( String.format( "Threshold detected for %s", threshold.getMinimum().getName() ) );

        List<DoSParam<?>> minParams = threshold.getMinimum().getCurrentParams();
        List<DoSParam<?>> maxParams = threshold.getMaximum().getCurrentParams();

        for ( int index = 0; index < minParams.size(); index++ )
        {
            DoSParam<?> minParam = minParams.get( index );
            DoSParam<?> maxParam = maxParams.get( index );

            if ( !minParam.getValueAsString().equals( maxParam.getValueAsString() ) )
            {
                LOG.info( " -> " + minParam.getDescription() + " " + minParam.getValueAsString() + " - "
                    + maxParam.getValueAsString() );
            }
        }

        thresholdList.add( threshold );
    }

    public static IDoSBuilder create()
    {
        return new IDoSBuilder();
    }

    public static class IDoSBuilder
    {

        private int serverRecoveryTime;

        private String xmlMessage;

        private PositionIterator positionIterator;

        private SuccessDecider successDecider;

        private DoSAttack[] dosAttackArray;

        private List<CommonParamItem> commonParamList;

        private IDoSBuilder()
        {

        }

        public IDoSBuilder withXmlMessage( String xmlMessage )
        {
            this.xmlMessage = xmlMessage;
            return this;
        }

        public IDoSBuilder withPositionIterator( PositionIterator positionIterator )
        {
            this.positionIterator = positionIterator;
            return this;
        }

        public IDoSBuilder withAttacks( DoSAttack[] dosAttackArray )
        {
            this.dosAttackArray = new DoSAttack[dosAttackArray.length];
            System.arraycopy( dosAttackArray, 0, this.dosAttackArray, 0, dosAttackArray.length );

            return this;
        }

        public IDoSBuilder withSuccessDecider( SuccessDecider successDecider )
        {
            this.successDecider = successDecider;
            return this;
        }

        public IDoSBuilder withCommonParams( List<CommonParamItem> commonParamList )
        {
            this.commonParamList = commonParamList;
            return this;
        }

        public IDoSBuilder withServerRecoveryTime( int serverRecoveryTime )
        {
            this.serverRecoveryTime = serverRecoveryTime;
            return this;
        }

        public IntelligentDoSLibrary build()
        {
            IntelligentDoSLibraryImpl intelligentDoSLibraryImpl =
                new IntelligentDoSLibraryImpl( this.xmlMessage, this.positionIterator );

            intelligentDoSLibraryImpl.setAttacks( this.dosAttackArray );
            intelligentDoSLibraryImpl.setSuccessDecider( this.successDecider );
            intelligentDoSLibraryImpl.setCommonParams( this.commonParamList );
            intelligentDoSLibraryImpl.setServerRecoveryTime( this.serverRecoveryTime );
            return intelligentDoSLibraryImpl;
        }

    }

}
