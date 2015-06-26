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
package wsattacker.library.intelligentdos.common;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.position.Position;

import com.google.common.collect.ImmutableList;

/**
 * @author Christian Altmeier
 */
public class AttackModel
{
    // If more that this value errors occure, the attack was not performed
    // successful. We cannot conclude anything useful then
    private static final double RATE_SUCCESSFUL_FAILED = 0.7;

    private int current;

    private CommonParamItem paramItem;

    private int serverRecoveryBeforeSend;

    private String requestContent;

    private Position position = null;

    private DoSAttack doSAttack = null;

    private PayloadPosition payloadPosition;

    private RequestType requestType;

    private final List<Metric> list;

    private final List<PropertyChangeListener> listeners;

    public AttackModel()
    {
        list = new ArrayList<Metric>();
        listeners = new ArrayList<PropertyChangeListener>();
    }

    public String getRequestContent()
    {
        return requestContent;
    }

    public void setRequestContent( String requestContent )
    {
        this.requestContent = requestContent;
    }

    public CommonParamItem getParamItem()
    {
        return paramItem;
    }

    public void setParamItem( CommonParamItem paramItem )
    {
        this.paramItem = paramItem;
    }

    public int getNumberOfRequests()
    {
        return paramItem != null ? paramItem.getNumberOfRequests() : 0;
    }

    public int getNumberOfThreads()
    {
        return paramItem != null ? paramItem.getNumberOfThreads() : 0;
    }

    public int getMilliesBetweenRequests()
    {
        return paramItem != null ? paramItem.getMilliesBetweenRequests() : 0;
    }

    public int getServerRecoveryBeforeSend()
    {
        return serverRecoveryBeforeSend;
    }

    public void setServerRecoveryBeforeSend( int serverRecoveryBeforeSend )
    {
        this.serverRecoveryBeforeSend = serverRecoveryBeforeSend;
    }

    public RequestType getRequestType()
    {
        return requestType;
    }

    public void setRequestType( RequestType requestType )
    {
        this.requestType = requestType;
    }

    public Position getPosition()
    {
        return position;
    }

    public void setPosition( Position position )
    {
        this.position = position;
    }

    public PayloadPosition getPayloadPosition()
    {
        return payloadPosition;
    }

    public void setPayloadPosition( PayloadPosition payloadPosition )
    {
        this.payloadPosition = payloadPosition;
    }

    public DoSAttack getDoSAttack()
    {
        return doSAttack;
    }

    public void setDoSAttack( DoSAttack doSAttack )
    {
        this.doSAttack = doSAttack;

    }

    public int getErrorCount()
    {
        int count = 0;

        for ( Metric metric : list )
        {
            if ( metric.isEmptyResponse() || metric.isConnectionReset() || metric.isReadTimedOut()
                || metric.isSOAPFault() )
            {
                count++;
            }
        }

        return count;
    }

    public int getSOAPFaultCount()
    {
        int count = 0;

        for ( Metric metric : list )
        {
            if ( metric.isSOAPFault() )
            {
                count++;
            }
        }

        return count;
    }

    public boolean wasAttackExecutionSuccessful()
    {
        if ( list.size() > 0 )
        {
            float rate = ( list.size() - getErrorCount() ) / ( list.size() * 1.0f );
            return rate > RATE_SUCCESSFUL_FAILED;
        }
        else
        {
            return true;
        }
    }

    public boolean isAllFail()
    {
        float e = getErrorCount() / ( list.size() * 1.0f );
        return e > 0.95;
    }

    public boolean isAllSOAPFault()
    {
        return getSOAPFaultCount() == list.size();
    }

    public List<Metric> getMetrics()
    {
        return ImmutableList.copyOf( list );
    }

    public Long[] getDurationArray()
    {
        Long[] array = new Long[list.size()];
        int i = 0;
        for ( Metric metric : list )
        {
            array[i++] = metric.getDuration();
        }
        return array;
    }

    public synchronized void addMetric( Metric metric )
    {
        list.add( metric );
    }

    public void increase()
    {
        int oldCurrent = current;
        current++;
        firePropertyChange( new PropertyChangeEvent( this, "current", oldCurrent, current ) );
    }

    public void addPropertyChangeListener( PropertyChangeListener listener )
    {
        listeners.add( listener );
    }

    public void removePropertyChangeListener( PropertyChangeListener listener )
    {
        listeners.remove( listener );
    }

    private void firePropertyChange( PropertyChangeEvent propertyChangeEvent )
    {
        for ( PropertyChangeListener listener : listeners )
        {
            listener.propertyChange( propertyChangeEvent );
        }
    }

    public int getProgress()
    {
        // percentage
        float total = getNumberOfRequests() * getNumberOfThreads() * 1.0f;
        float result = ( ( current * 1.0f ) / total ) * 100;
        return (int) result;
    }

    public static AttackModelBuilder custom()
    {
        return new AttackModelBuilder();
    }

    @Override
    public String toString()
    {
        return String.format( "AttackModel[a=%s, e=%s, p=%s]", doSAttack.getName(), position, payloadPosition );
    }

    public static class AttackModelBuilder
    {

        private DoSAttack doSAttack = null;

        private RequestType requestType;

        private PayloadPosition payloadPosition;

        private Position position = null;

        private CommonParamItem paramItem;

        private int recovery;

        public AttackModelBuilder withDoSAttack( DoSAttack doSAttack )
        {
            this.doSAttack = doSAttack;
            return this;
        }

        public AttackModelBuilder withRequestType( RequestType requestType )
        {
            this.requestType = requestType;
            return this;
        }

        public AttackModelBuilder withPayloadPosition( PayloadPosition payloadPosition )
        {
            this.payloadPosition = payloadPosition;
            return this;
        }

        public AttackModelBuilder withPosition( Position position )
        {
            this.position = position;
            return this;
        }

        public AttackModelBuilder withParamItem( CommonParamItem paramItem )
        {
            this.paramItem = paramItem;
            return this;
        }

        public AttackModelBuilder withRecovery( int recovery )
        {
            this.recovery = recovery;
            return this;
        }

        public AttackModel build()
        {
            AttackModel attackModel = new AttackModel();
            attackModel.setRequestType( this.requestType );
            try
            {
                // Clone the dos attack, else we manipulate the "original" and
                // cannot save the state
                attackModel.setDoSAttack( this.doSAttack.clone() );
            }
            catch ( CloneNotSupportedException e )
            {
                throw new RuntimeException( e );
            }
            attackModel.setPayloadPosition( this.payloadPosition );
            attackModel.setPosition( this.position );
            attackModel.setParamItem( this.paramItem );

            String xmlWithPlaceholder = this.position.createPlaceholder( this.payloadPosition );
            String content = "";
            if ( this.requestType == RequestType.TAMPERED )
            {
                content = doSAttack.getTamperedRequest( xmlWithPlaceholder, this.payloadPosition );
            }
            else if ( this.requestType == RequestType.UNTAMPERED )
            {
                content = doSAttack.getUntamperedRequest( xmlWithPlaceholder, this.payloadPosition );
            }
            attackModel.setRequestContent( content );

            attackModel.setServerRecoveryBeforeSend( this.recovery );

            return attackModel;
        }
    }

}
