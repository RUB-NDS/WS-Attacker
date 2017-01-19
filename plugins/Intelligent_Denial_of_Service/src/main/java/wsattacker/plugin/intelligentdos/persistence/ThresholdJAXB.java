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
import wsattacker.library.intelligentdos.common.Threshold;

/**
 * @author Christian Altmeier
 */
@XmlRootElement
public class ThresholdJAXB
{

    private DoSAttackJAXB minimum = null;

    private DoSAttackJAXB maximum = null;

    public DoSAttackJAXB getMinimum()
    {
        return minimum;
    }

    public void setMinimum( DoSAttackJAXB minimum )
    {
        this.minimum = minimum;
    }

    public DoSAttackJAXB getMaximum()
    {
        return maximum;
    }

    public void setMaximum( DoSAttackJAXB maximum )
    {
        this.maximum = maximum;
    }

    public Threshold toThreshold()
    {
        Threshold threshold = new Threshold( minimum.toDoSAttack(), maximum.toDoSAttack() );
        return threshold;
    }

    public static ThresholdJAXB fromThreshold( Threshold threshold )
    {

        ThresholdJAXB bdto = new ThresholdJAXB();
        bdto.setMinimum( DoSAttackJAXB.fromDoSAttack( threshold.getMinimum() ) );
        bdto.setMaximum( DoSAttackJAXB.fromDoSAttack( threshold.getMaximum() ) );

        return bdto;
    }
}
