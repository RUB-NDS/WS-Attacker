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

import com.google.common.collect.Lists;
import java.util.Date;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.plugin.intelligentdos.model.ResultModel;

/**
 * @author Christian Altmeier
 */
@XmlRootElement
public class AttackMetaDataJAXB
{

    private Date start;

    private Date stop;

    private double maximumRequestsPerSecond;

    private List<DoSAttackJAXB> notPossible = Lists.newArrayList();

    private List<ThresholdJAXB> thresholds = Lists.newArrayList();

    public Date getStart()
    {
        return new Date( start.getTime() );
    }

    public void setStart( Date start )
    {
        this.start = new Date( start.getTime() );
    }

    public Date getStop()
    {
        return new Date( stop.getTime() );
    }

    public void setStop( Date stop )
    {
        this.stop = new Date( stop.getTime() );
    }

    public double getMaximumRequestsPerSecond()
    {
        return maximumRequestsPerSecond;
    }

    public void setMaximumRequestsPerSecond( double maximumRequestsPerSecond )
    {
        this.maximumRequestsPerSecond = maximumRequestsPerSecond;
    }

    public List<DoSAttackJAXB> getNotPossible()
    {
        return notPossible;
    }

    public void setNotPossible( List<DoSAttackJAXB> notPossible )
    {
        this.notPossible = notPossible;
    }

    public List<ThresholdJAXB> getThresholds()
    {
        return thresholds;
    }

    public void setThresholds( List<ThresholdJAXB> threshold )
    {
        this.thresholds = threshold;
    }

    public ResultModel toResultModel()
    {
        ResultModel resultModel = new ResultModel();
        resultModel.setStartDate( start );
        resultModel.setStopDate( stop );
        resultModel.setMaximumRequestsPerSecond( maximumRequestsPerSecond );

        for ( DoSAttackJAXB jaxb : notPossible )
        {
            resultModel.getNotPossible().add( jaxb.toDoSAttack() );
        }

        for ( ThresholdJAXB jaxb : thresholds )
        {
            resultModel.getThresholds().add( jaxb.toThreshold() );
        }

        return resultModel;
    }

    public static AttackMetaDataJAXB fromResultModel( ResultModel resultModel )
    {
        AttackMetaDataJAXB attackMetaDataJAXB = new AttackMetaDataJAXB();
        attackMetaDataJAXB.setStart( resultModel.getStartDate() );
        attackMetaDataJAXB.setStop( resultModel.getStopDate() );
        attackMetaDataJAXB.setMaximumRequestsPerSecond( resultModel.getMaximumRequestsPerSecond() );

        for ( DoSAttack doSAttack : resultModel.getNotPossible() )
        {
            attackMetaDataJAXB.notPossible.add( DoSAttackJAXB.fromDoSAttack( doSAttack ) );
        }

        for ( Threshold threshold : resultModel.getThresholds() )
        {
            attackMetaDataJAXB.thresholds.add( ThresholdJAXB.fromThreshold( threshold ) );
        }

        return attackMetaDataJAXB;
    }

}
