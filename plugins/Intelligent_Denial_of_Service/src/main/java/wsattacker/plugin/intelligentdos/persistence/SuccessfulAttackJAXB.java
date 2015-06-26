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
package wsattacker.plugin.intelligentdos.persistence;

import javax.xml.bind.annotation.XmlRootElement;

import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.position.Position;

/**
 * @author Christian Altmeier
 */
@XmlRootElement( name = "successfulAttack" )
public class SuccessfulAttackJAXB
{

    private DoSAttackJAXB doSAttack;

    private PayloadPosition payloadPosition;

    private String nodeName;

    private int numberOfRequests, numberOfThreads, milliesBetweenRequests;

    public DoSAttackJAXB getDoSAttack()
    {
        return doSAttack;
    }

    public void setDoSAttack( DoSAttackJAXB doSAttack )
    {
        this.doSAttack = doSAttack;
    }

    public PayloadPosition getPayloadPosition()
    {
        return payloadPosition;
    }

    public void setPayloadPosition( PayloadPosition payloadPosition )
    {
        this.payloadPosition = payloadPosition;
    }

    public String getNodeName()
    {
        return nodeName;
    }

    public void setNodeName( String nodeName )
    {
        this.nodeName = nodeName;
    }

    public int getNumberOfRequests()
    {
        return numberOfRequests;
    }

    public void setNumberOfRequests( int numberOfRequests )
    {
        this.numberOfRequests = numberOfRequests;
    }

    public int getNumberOfThreads()
    {
        return numberOfThreads;
    }

    public void setNumberOfThreads( int numberOfThreads )
    {
        this.numberOfThreads = numberOfThreads;
    }

    public int getMilliesBetweenRequests()
    {
        return milliesBetweenRequests;
    }

    public void setMilliesBetweenRequests( int milliesBetweenRequests )
    {
        this.milliesBetweenRequests = milliesBetweenRequests;
    }

    public SuccessfulAttack toSuccessfulAttack()
    {
        CommonParamItem paramItem = new CommonParamItem( numberOfRequests, numberOfThreads, milliesBetweenRequests );

        SuccessfulAttack attackModel = new SuccessfulAttack( doSAttack.toDoSAttack(), paramItem );
        attackModel.setPayloadPosition( payloadPosition );
        attackModel.setPosition( new ResultPosition( nodeName ) );

        return attackModel;
    }

    public static SuccessfulAttackJAXB fromAttackModel( SuccessfulAttack successfulAttack )
    {
        CommonParamItem paramItem = successfulAttack.getParamItem();

        SuccessfulAttackJAXB am = new SuccessfulAttackJAXB();
        am.setDoSAttack( DoSAttackJAXB.fromDoSAttack( successfulAttack.getDoSAttack() ) );
        am.setNumberOfRequests( paramItem.getNumberOfRequests() );
        am.setNumberOfThreads( paramItem.getNumberOfThreads() );
        am.setMilliesBetweenRequests( paramItem.getMilliesBetweenRequests() );
        am.setPayloadPosition( successfulAttack.getPayloadPosition() );

        am.setNodeName( successfulAttack.getPosition().toString() );

        return am;
    }

    private class ResultPosition
        implements Position
    {
        private final String positionString;

        public ResultPosition( String positionString )
        {
            this.positionString = positionString;
        }

        @Override
        public String createPlaceholder( PayloadPosition payloadPosition )
        {
            return null;
        }

        @Override
        public int hashCode()
        {
            return positionString.hashCode();
        }

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

            ResultPosition that = (ResultPosition) obj;
            return nodeName.equals( that.positionString );
        };

        @Override
        public String toString()
        {
            return nodeName;
        };
    }

}
