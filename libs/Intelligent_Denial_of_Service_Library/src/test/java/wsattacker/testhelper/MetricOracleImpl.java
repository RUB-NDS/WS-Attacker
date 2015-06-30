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
package wsattacker.testhelper;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.DoSAttack;

/**
 * @author Christian Altmeier
 */
public class MetricOracleImpl
    implements MetricOracle
{

    private boolean allVulnerable = false;

    private int count = 24;

    private int successMultiplier = 8;

    private int duration = 1000;

    private String content = "OK";

    public String faultContent = "<fault></fault>";

    private SuccessfulAttack[] successfulAttacks;

    private Threshold[] thresholds;

    private double maxRequestsPerSecond;

    private int maxDocumentSize;

    private MetricOracleImpl()
    {

    }

    @Override
    public void createMetric( AttackModel attackModel )
    {

        if ( isASuccessfulAttack( attackModel ) )
        {
            fillInMetric( attackModel, successMultiplier * duration );
        }
        else if ( isAMaxRequest( attackModel ) )
        {
            fillInFault( attackModel, duration, (int) ( maxRequestsPerSecond / 2 ) );
        }
        else if ( isDocumentSizeExpired( attackModel ) )
        {
            fillInFault( attackModel, duration );
        }
        else if ( isAThresholdAttack( attackModel ) )
        {
            fillInFault( attackModel, duration );
        }
        else
        {
            fillInMetric( attackModel, duration );
        }
    }

    private boolean isASuccessfulAttack( AttackModel attackModel )
    {
        if ( allVulnerable && attackModel.getRequestType() == RequestType.TAMPERED )
        {
            return true;
        }

        if ( successfulAttacks == null )
        {
            return false;
        }

        for ( SuccessfulAttack successfulAttack : successfulAttacks )
        {
            DoSAttack dos1 = successfulAttack.getDoSAttack();
            DoSAttack dos2 = attackModel.getDoSAttack();
            if ( dos1.equals( dos2 ) && dos2.compareTo( dos1 ) >= 0
                && successfulAttack.getPayloadPosition() == attackModel.getPayloadPosition()
                && successfulAttack.getPosition().equals( attackModel.getPosition() )
                && attackModel.getParamItem().compareTo( successfulAttack.getParamItem() ) >= 0 )
            {
                return true;
            }
        }

        return false;
    }

    private boolean isAMaxRequest( AttackModel attackModel )
    {
        return maxRequestsPerSecond > 0 && attackModel.getParamItem().getReuqestsPerSecond() > maxRequestsPerSecond;
    }

    private boolean isDocumentSizeExpired( AttackModel attackModel )
    {
        return maxDocumentSize > 0 && attackModel.getRequestContent().length() > maxDocumentSize;
    }

    private boolean isAThresholdAttack( AttackModel attackModel )
    {
        if ( attackModel.getRequestType() == RequestType.UNTAMPERED || thresholds == null )
        {
            return false;
        }

        for ( Threshold threshold : thresholds )
        {
            DoSAttack dos = attackModel.getDoSAttack();

            if ( dos.getName().equals( threshold.getMinimum().getName() )
                && dos.compareTo( threshold.getMinimum() ) > 0 )
            {
                return true;
            }
        }

        return false;
    }

    private void fillInMetric( AttackModel attackModel, int effectiveDuration )
    {
        for ( int i = 0; i < count; i++ )
        {
            Metric metric = new Metric();
            metric.setDuration( effectiveDuration );
            metric.setContent( content );
            attackModel.addMetric( metric );
        }
    }

    private void fillInFault( AttackModel attackModel, int effectiveDuration )
    {
        for ( int i = 0; i < count; i++ )
        {
            Metric metric = new Metric();
            metric.setDuration( effectiveDuration );
            metric.setContent( faultContent );
            attackModel.addMetric( metric );
        }
    }

    private void fillInFault( AttackModel attackModel, int effectiveDuration, int faultCount )
    {
        for ( int i = 0; i < count - faultCount; i++ )
        {
            Metric metric = new Metric();
            metric.setDuration( effectiveDuration );
            metric.setContent( content );
            attackModel.addMetric( metric );
        }

        for ( int i = 0; i < faultCount; i++ )
        {
            Metric metric = new Metric();
            metric.setDuration( effectiveDuration );
            metric.setContent( faultContent );
            attackModel.addMetric( metric );
        }
    }

    public static class MetricOracleBuilder
    {
        boolean allVulnerable = false;

        private int count = 24;

        private int duration = 1000;

        private int successMultiplier = 8;

        private String content = "OK";

        private String faultContent = "<fault></fault>";

        private SuccessfulAttack[] successfulAttacks;

        private Threshold[] thresholds;

        private double maxRequestsPerSecond;

        private int maxDocumentSize;

        private MetricOracleBuilder()
        {

        }

        public static MetricOracleBuilder create()
        {
            return new MetricOracleBuilder();
        }

        public MetricOracleBuilder withAllVulnerable( boolean allVulnerable )
        {
            this.allVulnerable = allVulnerable;
            return this;
        }

        public MetricOracleBuilder withCount( int count )
        {
            this.count = count;
            return this;
        }

        public MetricOracleBuilder withDuration( int duration )
        {
            this.duration = duration;
            return this;
        }

        public MetricOracleBuilder withSuccessMultiplier( int successMultiplier )
        {
            this.successMultiplier = successMultiplier;
            return this;
        }

        public MetricOracleBuilder withContent( String content )
        {
            this.content = content;
            return this;
        }

        public MetricOracleBuilder withFaultContent( String faultContent )
        {
            this.faultContent = faultContent;
            return this;
        }

        public MetricOracleBuilder withVulnerable( SuccessfulAttack... successfulAttacks )
        {
            this.successfulAttacks = successfulAttacks;
            return this;
        }

        public MetricOracleBuilder withThreshold( Threshold... thresholds )
        {
            this.thresholds = thresholds;
            return this;
        }

        public MetricOracleBuilder withMaxRequestsPerSecond( double maxRequestsPerSecond )
        {
            this.maxRequestsPerSecond = maxRequestsPerSecond;
            return this;
        }

        public MetricOracleBuilder withMaxDocumentSize( int maxDocumentSize )
        {
            this.maxDocumentSize = maxDocumentSize;
            return this;
        }

        public MetricOracle build()
        {
            MetricOracleImpl oracle = new MetricOracleImpl();
            oracle.allVulnerable = this.allVulnerable;
            oracle.count = this.count;
            oracle.duration = this.duration;
            oracle.successMultiplier = this.successMultiplier;
            oracle.content = this.content;
            oracle.faultContent = this.faultContent;
            oracle.successfulAttacks = this.successfulAttacks;
            oracle.thresholds = this.thresholds;
            oracle.maxRequestsPerSecond = this.maxRequestsPerSecond;
            oracle.maxDocumentSize = this.maxDocumentSize;

            return oracle;
        }

    }

}
